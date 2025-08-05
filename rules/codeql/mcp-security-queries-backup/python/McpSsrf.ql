/**
 * @name Server-side request forgery in MCP tool
 * @description An MCP tool parameter is used to construct a URL for an HTTP request,
 *              which can allow attackers to make arbitrary requests to internal or
 *              external services.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id py/mcp-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.security.dataflow.ServerSideRequestForgery

/**
 * A data flow source for SSRF vulnerabilities in MCP servers.
 */
class McpToolParameterSource extends ServerSideRequestForgery::Source {
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
 * A configuration for taint tracking from MCP tool parameters to HTTP request sinks.
 */
class McpSsrfConfig extends ServerSideRequestForgery::Configuration {
  McpSsrfConfig() { this = "McpSsrfConfig" }

  override predicate isSource(ServerSideRequestForgery::Source source) {
    source instanceof McpToolParameterSource
  }
}

from McpSsrfConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This request depends on a user-provided MCP tool parameter."