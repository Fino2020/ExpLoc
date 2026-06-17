/**
 * @name Inter-procedural Call Graph (Python)
 * @description Extracts call edges where the callee can be statically resolved.
 * @kind table
 * @id python/inter-procedural-cfg
 */

import python

from Call c, Function caller, string calleeName, int srcLine
where
  c.getScope() = caller and
  srcLine = c.getLocation().getStartLine() and
  calleeName = c.getFunc().toString()
select
  caller.getEnclosingModule().getFile().getRelativePath() as file,
  caller.getName() as function,
  srcLine,
  calleeName as callee_expression
