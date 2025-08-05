/**
 * @name Command injection in MCP tool
 * @description An MCP tool parameter is used to construct a shell command, which can allow
 *              remote attackers to execute arbitrary commands on the server.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/mcp-command-injection
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import python
import semmle.python.security.dataflow.CommandInjection

/**
 * A data flow source for command injection vulnerabilities in MCP servers.
 * This class models any parameter of a function decorated as an MCP tool.
 */
class McpToolParameterSource extends CommandInjection::Source {
  McpToolParameterSource() {
    // A parameter of a function that has an `@mcp.tool()` or similar decorator.
    exists(Function f, Decorator d, Parameter p |
      this.asParameter() = p and
      p.getFunction() = f and
      f.getAdecorator() = d and
      // Match decorators like `@mcp.tool`, `@fastmcp.tool`, or any variable ending in `mcp`
      // followed by `.tool`. This covers common MCP framework patterns.
      d.asCall().getFunc().(Attribute).getName() = "tool" and
      d.asCall().getFunc().(Attribute).getObject().(Name).getId().regexpMatch("(?i).*(mcp|app|server)")
    )
  }
}

/**
 * A configuration for taint tracking from MCP tool parameters to command execution sinks.
 */
class McpCommandInjectionConfig extends CommandInjection::Configuration {
  McpCommandInjectionConfig() { this = "McpCommandInjectionConfig" }

  override predicate isSource(CommandInjection::Source source) {
    source instanceof McpToolParameterSource
  }
}

from McpCommandInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This command depends on a user-provided MCP tool parameter."