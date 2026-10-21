/**
 * @name Inter-procedural Call Graph (Go)
 * @description Extracts call edges — method chaining avoids type-declaration issues.
 * @kind table
 * @id go/inter-procedural-cfg
 */

import go

from CallExpr ce
where
  ce.getLocation().getStartLine() > 0 and
  ce.getCalleeName() != ""
select
  ce.getEnclosingFunction().getLocation().getFile().getRelativePath() as file,
  ce.getEnclosingFunction().getName() as function,
  ce.getLocation().getStartLine() as src_line,
  ce.getTarget().getLocation().getStartLine() as dst_line,
  ce.getCalleeName() as callee_name
