import cpp

// SARIF omits some diagnostics from system headers. They can still invalidate
// application types even when a compilation terminates normally.
from Diagnostic d, string sourcePath
where
  d.getSeverity() >= 3 and
  (
    sourcePath = d.getFile().getRelativePath()
    or
    not exists(d.getFile().getRelativePath()) and sourcePath = d.getFile().getAbsolutePath()
  )
select d.getCompilation().toString() as compilation, sourcePath as path,
  d.getLocation().getStartLine() as line, d.getSeverity() as severity,
  d.getMessage() as message
