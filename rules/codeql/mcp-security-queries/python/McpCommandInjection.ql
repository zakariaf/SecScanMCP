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
 *       mcp
 */

import python
import semmle.python.security.dataflow.CommandInjection
import DataFlow::PathGraph

/**
 * A data flow source for command injection vulnerabilities in MCP servers.
 */
class McpToolParameterSource extends DataFlow::Node {
  McpToolParameterSource() {
    exists(Function f |
      // Pattern 1: Functions decorated with MCP tool decorators
      exists(Decorator d |
        f.getADecorator() = d and
        (
          // @mcp.tool(), @fastmcp.tool(), etc.
          d.getName() = "tool" and
          exists(Attribute attr |
            attr = d.getFunc() and
            attr.getObject().(Name).getId().regexpMatch("(?i).*(mcp|app|server)")
          )
          or
          // Direct decorator like @tool
          d.getName().regexpMatch("(?i).*(mcp_tool|mcptool|tool)")
        )
      )
      or
      // Pattern 2: Methods in MCP server classes
      exists(Class cls |
        f.getScope() = cls and
        cls.getName().regexpMatch("(?i).*(MCP|Mcp|Tool|Server).*") and
        f.getName().regexpMatch("(?i).*(tool|command|execute|run|handle).*")
      )
    ) and
    this = DataFlow::parameterNode(f.getArg(_))
  }
}

/**
 * Configuration for tracking command injection from MCP inputs.
 */
class McpCommandInjectionConfig extends TaintTracking::Configuration {
  McpCommandInjectionConfig() { this = "McpCommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameterSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandInjection::Sink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Shell escape functions
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asCfgNode().(NameNode).getId() in [
        "shlex.quote", "pipes.quote", "escape_shell", "sanitize_command"
      ] and
      node = call.getArg(0)
    )
  }
}

from McpCommandInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection vulnerability: shell command depends on MCP tool parameter from $@.",
  source.getNode(), "here"