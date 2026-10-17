// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

// Read the real installed program's list-view cells. The ARM64 CI desktop's
// UI Automation provider exposes these controls as empty generic panes.
public static class TestListViewReader
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Item
    {
        public uint mask;
        public int row, column;
        public uint state, stateMask;
        public IntPtr text;
        public int capacity, image;
        public IntPtr parameter;
        public int indent, groupId;
        public uint columns;
        public IntPtr columnIndices, columnFormats;
        public int group;
    }
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetDlgItem(IntPtr window, int id);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, IntPtr wparam, IntPtr lparam, uint flags, uint timeout, out UIntPtr result);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint id);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, UIntPtr size, uint allocation, uint protection);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(IntPtr process, IntPtr address, UIntPtr size, uint type);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr written);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr read);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static ulong Message(IntPtr window, uint message, int row, IntPtr data)
    {
        UIntPtr result;
        if (SendMessageTimeout(window, message, new IntPtr(row), data, 3, 3000, out result) == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "The tested list view did not respond.");
        return result.ToUInt64();
    }

    public static string[] Read(int processId, IntPtr window)
    {
        if (IntPtr.Size != 8) throw new InvalidOperationException("Use native x64/ARM64 PowerShell for these installer tests.");
        var list = GetDlgItem(window, 231); // IDC_HASH_LIST
        uint owner;
        if (list == IntPtr.Zero || GetWindowThreadProcessId(list, out owner) == 0 || owner != (uint)processId)
            throw new InvalidOperationException("The expected process does not own the hash list.");
        ulong count = Message(list, 0x1004, 0, IntPtr.Zero); // LVM_GETITEMCOUNT
        if (count > 128) throw new InvalidOperationException("Unexpected row count for the single-file fixture.");
        var rows = new string[(int)count];
        if (count == 0) return rows;
        var process = OpenProcess(0x38, false, (uint)processId); // VM_OPERATION | VM_READ | VM_WRITE
        if (process == IntPtr.Zero) throw new Win32Exception();
        IntPtr remote = IntPtr.Zero, local = IntPtr.Zero;
        try
        {
            int size = Marshal.SizeOf(typeof(Item));
            remote = VirtualAllocEx(process, IntPtr.Zero, new UIntPtr((uint)(size + 1024)), 0x3000, 4);
            if (remote == IntPtr.Zero) throw new Win32Exception();
            local = Marshal.AllocHGlobal(size);
            var itemBytes = new byte[size];
            var textBytes = new byte[1024];
            for (int row = 0; row < rows.Length; ++row)
            {
                var cells = new string[2];
                for (int column = 1; column <= 2; ++column)
                {
                    var item = new Item { row = row, column = column, text = IntPtr.Add(remote, size), capacity = 512 };
                    Marshal.StructureToPtr(item, local, false);
                    Marshal.Copy(local, itemBytes, 0, size);
                    UIntPtr transferred;
                    if (!WriteProcessMemory(process, remote, itemBytes, new UIntPtr((uint)size), out transferred) || transferred.ToUInt64() != (uint)size)
                        throw new Win32Exception();
                    ulong length = Message(list, 0x1073, row, remote); // LVM_GETITEMTEXTW
                    if (length >= 512) throw new InvalidOperationException("Invalid list-view text length.");
                    uint bytes = (uint)(length + 1) * 2;
                    if (!ReadProcessMemory(process, item.text, textBytes, new UIntPtr(bytes), out transferred) || transferred.ToUInt64() != bytes)
                        throw new Win32Exception();
                    cells[column - 1] = Encoding.Unicode.GetString(textBytes, 0, (int)length * 2);
                }
                rows[row] = cells[0] + "\t" + cells[1];
            }
            return rows;
        }
        finally
        {
            if (local != IntPtr.Zero) Marshal.FreeHGlobal(local);
            if (remote != IntPtr.Zero) VirtualFreeEx(process, remote, UIntPtr.Zero, 0x8000);
            CloseHandle(process);
        }
    }
}
