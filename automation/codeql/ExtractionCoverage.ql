import cpp

// Query the actual database: a successful compiler or SARIF upload does not
// prove that the extractor retained every translation unit.
from File f
where
  exists(f.getRelativePath()) and
  (exists(Compilation c | c.getAFileCompiled() = f) or
    f.getRelativePath() = "Algorithms/extended/sphlib/md_helper.c" or
    f.getRelativePath() = "OpenHashTab/OpenHashTab/json.h")
select f.getRelativePath() as path,
  count(Compilation c | c.getAFileCompiled() = f and c.normalTermination()) as completed,
  count(Compilation c | c.getAFileCompiled() = f and not c.normalTermination()) as crashed,
  count(File parsed | parsed = f and parsed.fromSource()) as parsed,
  count(Function fn | fn.getFile() = f) as functions
