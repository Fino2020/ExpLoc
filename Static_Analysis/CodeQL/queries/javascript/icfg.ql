/**
 * @name Inter-procedural Call Graph (JavaScript)
 * @description Extracts call edges with statically known targets.
 * @kind table
 * @id javascript/inter-procedural-cfg
 */

import javascript

from CallExpr ce, Function caller, int srcLine, string calleeName, int dstLine
where
  ce.getEnclosingFunction() = caller and
  srcLine = ce.getLocation().getStartLine() and
  (
    if exists(ce.getCallee().(Function).getName())
    then calleeName = ce.getCallee().(Function).getName() and
         dstLine = ce.getCallee().getLocation().getStartLine()
    else calleeName = ce.getCalleeName() and dstLine = 0
  )
select
  caller.getFile().getRelativePath() as file,
  caller.getName() as function,
  srcLine,
  dstLine,
  calleeName as callee_target
