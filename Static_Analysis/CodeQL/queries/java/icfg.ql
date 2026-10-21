/**
 * @name Inter-procedural Call Graph (Java)
 * @description Extracts call edges from call sites to callee methods.
 *              Uses only stable import java API — no internal controlflow modules.
 * @kind table
 * @id java/inter-procedural-cfg
 */

import java

from Callable caller, Call c, Callable callee, int srcLine, int dstLine
where
  c.getEnclosingCallable() = caller and
  c.getCallee() = callee and
  srcLine = c.getLocation().getStartLine() and
  dstLine = callee.getLocation().getStartLine()
select
  caller.getCompilationUnit().getRelativePath() as file,
  caller.getName() as function,
  srcLine,
  dstLine,
  "call" as edge_type,
  callee.getName() as target
