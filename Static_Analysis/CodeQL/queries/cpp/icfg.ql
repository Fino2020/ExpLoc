/**
 * @name Inter-procedural CFG (C++)
 * @description ICFG combining intra-procedural CFG edges with call/return edges.
 *              Uses only the stable import cpp API — no internal controlflow modules.
 * @kind table
 * @id cpp/inter-procedural-cfg
 */

import cpp

from Function func, int srcLine, int dstLine, string edgeType, string target
where
  not func.getFile().getRelativePath().matches("usr/%") and
  (
    // Intra-procedural CFG: ControlFlowNode successor edges within the same function
    exists(ControlFlowNode src, ControlFlowNode dst |
      dst = src.getASuccessor() and
      src.getControlFlowScope() = func and
      srcLine = src.getLocation().getStartLine() and
      dstLine = dst.getLocation().getStartLine() and
      edgeType = "cfg" and target = ""
    )
    or
    // Call edge: call site -> callee entry
    exists(FunctionCall fc, Function callee |
      fc.getControlFlowScope() = func and
      fc.getTarget() = callee and
      srcLine = fc.getLocation().getStartLine() and
      dstLine = callee.getEntryPoint().getLocation().getStartLine() and
      edgeType = "call" and target = callee.getName()
    )
    or
    // Return edge: callee -> instruction after call site
    exists(FunctionCall fc, Function callee, ControlFlowNode retNode |
      fc.getControlFlowScope() = func and
      fc.getTarget() = callee and
      retNode = fc.getASuccessor() and
      srcLine = callee.getLocation().getEndLine() and
      dstLine = retNode.getLocation().getStartLine() and
      edgeType = "return" and target = callee.getName()
    )
  )
select
  func.getFile().getRelativePath() as file,
  func.getName() as function,
  srcLine,
  dstLine,
  edgeType as edge_type,
  target as target_function
