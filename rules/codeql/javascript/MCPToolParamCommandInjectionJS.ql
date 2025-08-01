/**
 * @name MCP JS tool param → command execution
 * @description Untrusted tool parameters flow into child_process exec/spawn
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @tags security mcp injection command-injection
 * @cwe CWE-78
 */

import javascript
import DataFlow
import TaintTracking

class ToolFunction extends Function {
  ToolFunction() {
    // Heuristic: functions exported as tools or annotated; adjust as needed
    this.getName().regexpMatch(".*Tool$") or
    exists(Export e | e.getExported() = this)
  }
}

class ToolParamSource extends DataFlow::Node {
  ToolParamSource() {
    exists(ToolFunction f, Parameter p, Identifier i |
      p = f.getAParameter() and
      i.getTarget() = p and
      this.asExpr() = i
    )
  }
}

class ExecSink extends DataFlow::Node {
  ExecSink() {
    exists(Call c |
      c.getCallee().getQualifiedName().matches("child_process.exec%") or
      c.getCallee().getQualifiedName().matches("child_process.spawn%") |
      this.asExpr() = c.getAnArgument()
    )
  }
}

class Cfg extends TaintTracking::Configuration {
  Cfg() { this = "MCPToolParamCommandInjectionJS" }
  override predicate isSource(DataFlow::Node s) { s instanceof ToolParamSource }
  override predicate isSink(DataFlow::Node s)   { s instanceof ExecSink }
}

from Cfg cfg, DataFlow::PathNode src, DataFlow::PathNode snk
where cfg.hasFlowPath(src, snk)
select snk.getNode(), src, snk,
  "Untrusted tool parameter flows to command execution.",
  src.getNode(), "tool parameter"
