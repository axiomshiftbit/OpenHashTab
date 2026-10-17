// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

// CreateProcessWithLogonW requires the caller to grant desktop/window-station
// access to the new user. Used only in guarded disposable-machine tests.
public sealed class TestDesktopAccess : IDisposable
{
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetProcessWindowStation();
    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetUserObjectSecurity(IntPtr handle, ref uint info, byte[] descriptor, uint size, out uint needed);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetUserObjectSecurity(IntPtr handle, ref uint info, byte[] descriptor);

    private readonly List<KeyValuePair<IntPtr, byte[]>> originals = new List<KeyValuePair<IntPtr, byte[]>>();

    public TestDesktopAccess(string sid)
    {
        try
        {
            Grant(GetProcessWindowStation(), sid, 0x37f); // WINSTA_ALL_ACCESS
            Grant(GetThreadDesktop(GetCurrentThreadId()), sid, 0x1ff); // DESKTOP_ALL_ACCESS
        }
        catch { Dispose(); throw; }
    }

    private void Grant(IntPtr handle, string sid, int mask)
    {
        if (handle == IntPtr.Zero) throw new Win32Exception();
        uint info = 4; // DACL_SECURITY_INFORMATION
        uint needed;
        GetUserObjectSecurity(handle, ref info, null, 0, out needed);
        if (needed == 0) throw new Win32Exception();
        var original = new byte[needed];
        if (!GetUserObjectSecurity(handle, ref info, original, needed, out needed)) throw new Win32Exception();
        var descriptor = new RawSecurityDescriptor(original, 0);
        if (descriptor.DiscretionaryAcl == null) return; // A null DACL already grants access.
        int index = 0;
        while (index < descriptor.DiscretionaryAcl.Count &&
               (descriptor.DiscretionaryAcl[index].AceFlags & AceFlags.Inherited) == 0) ++index;
        descriptor.DiscretionaryAcl.InsertAce(index,
            new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, mask, new SecurityIdentifier(sid), false, null));
        var updated = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(updated, 0);
        if (!SetUserObjectSecurity(handle, ref info, updated)) throw new Win32Exception();
        originals.Add(new KeyValuePair<IntPtr, byte[]>(handle, original));
    }

    public void Dispose()
    {
        int error = 0;
        for (int i = originals.Count - 1; i >= 0; --i)
        {
            uint info = 4;
            if (!SetUserObjectSecurity(originals[i].Key, ref info, originals[i].Value))
                error = Marshal.GetLastWin32Error();
        }
        originals.Clear();
        // The handles are borrowed from the process/thread, not owned here.
        if (error != 0) throw new Win32Exception(error);
    }
}
