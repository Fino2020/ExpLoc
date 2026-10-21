/**
 * @name Inter-procedural Call Graph (Ruby)
 * @description Extracts method call sites.
 * @kind table
 * @id ruby/inter-procedural-cfg
 */

import codeql.ruby.AST

from MethodCall c
where
  c.getLocation().getStartLine() > 0 and
  exists(c.getEnclosingMethod())
select
  c.getFile().getRelativePath() as file,
  c.getEnclosingMethod().getName() as caller,
  c.getLocation().getStartLine() as src_line,
  c.getMethodName() as callee_method
