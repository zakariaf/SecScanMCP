/**
 * @name MCP tool param → file write (potential path traversal)
 * @description Tool parameters reach file-write sinks without validation
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @tags security mcp path-traversal
 * @cwe CWE-22
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class MCPToolFunction extends Function {
  MCPToolFunction() {
    exists(Decorator d | d = this.getADecorator() and d.getName() = "tool") or
    this.getName().regexpMatch(".*_tool$")
  }
}

class ToolParamAccess extends DataFlow::Node {
  ToolParamAccess() {
    exists(MCPToolFunction f, Parameter p, Name n |
      p = f.getAParameter() and n = p.getAnAccess() and this.asExpr() = n
    )
  }
}

/** A call that writes to the filesystem (open with write/append/exclusive). */
class FileWriteArg extends DataFlow::Node {
  FileWriteArg() {
    exists(CallNode c |
      c.getCallee().getName() = "open" and
      // first arg is filename
      this.asExpr() = c.getArgument(0) and
      exists(Expr mode |
        // mode is 2nd arg; look for write-ish modes if present
        mode = c.getArgument(1) and mode.toString().regexpMatch(".*[wax].*")
        or
        // no mode given: default is read; we still flag for review if joined with dir traversal dots
        c.getNumberOfArguments() = 1
      )
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "MCPToolParamPathTraversal" }
  override predicate isSource(DataFlow::Node src) { src instanceof ToolParamAccess }
  override predicate isSink(DataFlow::Node snk)   { snk instanceof FileWriteArg }
}

from Config cfg, DataFlow::PathNode src, DataFlow::PathNode snk
where cfg.hasFlowPath(src, snk)
select snk.getNode(), src, snk,
  "Untrusted tool parameter reaches a file write; validate and normalize paths.",
  src.getNode(), "tool parameter"
