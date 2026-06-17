/**
 * @name Rust API Discovery v2
 * @description Test Rust types step by step.
 * @kind table
 * @id rust/api-discovery
 */

import rust

from CallExpr c
where
  c.getLocation().getStartLine() > 0
select
  c.getLocation().getStartLine() as line,
  c.getFunction().toString() as func_expr
