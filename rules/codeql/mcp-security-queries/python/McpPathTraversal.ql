/**
 * @name Path traversal in MCP tool
 * @description An MCP tool parameter is used to construct a file path, which can allow
 *              attackers to access arbitrary files on the server's file system.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/mcp-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 */

import python
import semmle.python.security.dataflow.PathInjection

/**
 * A data flow source for path traversal vulnerabilities in MCP servers.
 */
class McpToolParameterSource extends PathInjection::Source {
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
 * A configuration for taint tracking from MCP tool parameters to file system sinks.
 */
class McpPathTraversalConfig extends PathInjection::Configuration {
  McpPathTraversalConfig() { this = "McpPathTraversalConfig" }

  override predicate isSource(PathInjection::Source source) {
    source instanceof McpToolParameterSource
  }
}

from McpPathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This file path depends on a user-provided MCP tool parameter."