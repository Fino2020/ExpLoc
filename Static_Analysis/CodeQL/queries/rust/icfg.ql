/**
 * @name Inter-procedural Call Graph (Rust)
 * @description Extracts call site information.
 * @kind table
 * @id rust/inter-procedural-cfg
 */

import rust

from CallExpr c
where
  c.getLocation().getStartLine() > 0 and
  c.getEnclosingCallable() instanceof Function
select
  c.getEnclosingCallable().(Function).getLocation().getFile().getRelativePath() as file,
  c.getEnclosingCallable().(Function).getName() as function,
  c.getLocation().getStartLine() as src_line,
  c.getFunction().toString() as callee_name
