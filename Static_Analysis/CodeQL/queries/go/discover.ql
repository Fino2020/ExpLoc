/**
 * @name Go API Discovery
 * @description Figure out what methods are available on Go CallExpr and related types.
 * @kind table
 * @id go/api-discovery
 */

import go

// Test 1: What types does getTarget() return, and what methods are available?
from CallExpr ce
where
  ce.getLocation().getStartLine() > 0
select
  ce.getLocation().getStartLine() as line,
  ce.getTarget().toString() as target_str,
  ce.getTarget().getPrimaryQlClass() as target_type
