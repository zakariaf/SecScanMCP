/**
 * @name MCP tool param → command execution
 * @description Untrusted tool parameters flow into os.system/subprocess.*
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @tags security mcp injection command-injection
 * @cwe CWE-78
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** A function decorated as a tool (mcp.tool() / server.tool()). */
class MCPToolFunction extends Function {
  MCPToolFunction() {
    exists(Decorator d |
      d = this.getADecorator() and
      d.getName() = "tool"
    )
    or
    this.getName().regexpMatch(".*_tool$")
  }
}

/** Sources: any access to a parameter of a tool function. */
class ToolParamAccess extends DataFlow::Node {
  ToolParamAccess() {
    exists(MCPToolFunction f, Parameter p, Name n |
      p = f.getAParameter() and
      n = p.getAnAccess() and
      this.asExpr() = n
    )
  }
}

/** Sinks: arguments to os.system / subprocess.{run,Popen,call}. */
class CommandExecArg extends DataFlow::Node {
  CommandExecArg() {
    exists(CallNode c, API::Node api |
      (
        api = API::moduleImport("os").getMember("system") or
        api = API::moduleImport("subprocess").getMember(["run", "Popen", "call"])
      ) and
      c = api.getACall() and
      this.asExpr() = c.getAnArg()
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "MCPToolParamCommandInjection" }

  override predicate isSource(DataFlow::Node src) { src instanceof ToolParamAccess }
  override predicate isSink(DataFlow::Node snk)    { snk instanceof CommandExecArg }
}

from Config cfg, DataFlow::PathNode src, DataFlow::PathNode snk
where cfg.hasFlowPath(src, snk)
select snk.getNode(), src, snk,
  "Untrusted tool parameter flows to command execution.",
  src.getNode(), "tool parameter"
