/**
 * @name Code injection in MCP tool
 * @description An MCP tool parameter is evaluated as code or insecurely deserialized, which
 *              can allow remote attackers to execute arbitrary code on the server.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id py/mcp-code-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-502
 */

import python
import semmle.python.security.dataflow.CodeInjection

/**
 * A data flow source for code injection vulnerabilities in MCP servers.
 * This class models any parameter of a function decorated as an MCP tool.
 * It reuses the definition from the command injection query.
 */
class McpToolParameterSource extends CodeInjection::Source {
  McpToolParameterSource() {
    exists(Function f, Decorator d, Parameter p |
      this.asParameter() = p and
      p.getFunction() = f and
      f.getAdecorator() = d and
      d.asCall().getFunc().(Attribute).getName() = "tool" and
      d.asCall().getFunc().(Attribute).getObject().(Name).getId().regexpMatch("(?i).*(mcp|app|server)")
    )
  }
}

/**
 * A configuration for taint tracking from MCP tool parameters to code execution sinks.
 */
class McpCodeInjectionConfig extends CodeInjection::Configuration {
  McpCodeInjectionConfig() { this = "McpCodeInjectionConfig" }

  override predicate isSource(CodeInjection::Source source) {
    source instanceof McpToolParameterSource
  }
}

from McpCodeInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This code depends on a user-provided MCP tool parameter."