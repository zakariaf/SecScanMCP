/**
 * @name Code injection in MCP tool
 * @description An MCP tool parameter is evaluated as code, which can allow remote attackers
 *              to execute arbitrary code on the server.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id js/mcp-code-injection
 * @tags security
 *       external/cwe/cwe-094
 *       mcp
 */

import javascript
import semmle.javascript.security.dataflow.CodeInjection
import DataFlow::PathGraph

/**
 * A data flow source for code injection vulnerabilities in MCP servers.
 */
class McpToolParameterSource extends DataFlow::Node {
  McpToolParameterSource() {
    exists(Function f |
      // Match functions that are MCP tool handlers
      (
        // Pattern 1: Methods in MCP-related classes
        f instanceof Method and
        f.getDeclaringType().getName().regexpMatch("(?i).*(MCP|Mcp|Tool|Server).*") and
        f.getName().regexpMatch("(?i).*(tool|command|execute|run|handle).*")
        or
        // Pattern 2: Functions with MCP-related decorators (TypeScript)
        exists(Decorator d |
          f.getADecorator() = d and
          d.getDecoratorName().regexpMatch("(?i).*(mcp|tool).*")
        )
        or
        // Pattern 3: Tool handler functions in MCP server implementations
        exists(DataFlow::PropWrite pw |
          pw.getPropertyName() = "tools" and
          pw.getRhs().getALocalSource().asExpr().(ObjectExpr).getAProperty().getInit() = f
        )
      ) and
      this = DataFlow::parameterNode(f.getParameter(_))
    )
  }
}

/**
 * Configuration for tracking taint from MCP parameters to code execution sinks.
 */
class McpCodeInjectionConfig extends TaintTracking::Configuration {
  McpCodeInjectionConfig() { this = "McpCodeInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameterSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CodeInjection::Sink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // JSON parsing often prevents code injection
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef("JSON").getAMemberCall("parse") and
      node = call.getAnArgument()
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through property access on tool parameters
    exists(DataFlow::PropRead pr |
      pr.getBase() = pred and
      succ = pr
    )
  }
}

from McpCodeInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Code injection from MCP tool parameter $@.", source.getNode(), "here"