/**
 * @name Server-side request forgery in MCP tool
 * @description An MCP tool parameter is used to construct a URL for an HTTP request,
 *              which can allow attackers to make arbitrary requests to internal or
 *              external services.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id js/mcp-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import javascript
import semmle.javascript.security.dataflow.TaintTracking
import semmle.javascript.security.dataflow.ServerSideRequestForgery

/**
 * A data flow source for SSRF vulnerabilities in MCP servers.
 */
class McpToolParameterSource extends DataFlow::Node {
  McpToolParameterSource() {
    exists(Function f, Parameter p | this = DataFlow::parameterNode(p) and p.getFunction() = f |
      f instanceof Method and
      f.getDeclaringType().getName().regexpMatch("(?i).*(MCP|Mcp|Tool|Server).*") and
      f.getName().regexpMatch("(?i).*(tool|fetch|request|get).*")
    )
  }
}

/**
 * A configuration for taint tracking from MCP tool parameters to HTTP request sinks.
 */
module McpSsrfConfig implements TaintTracking::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameterSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof ServerSideRequestForgery::Sink
  }
}

module McpSsrfFlow = TaintTracking::Global<McpSsrfConfig>;

from DataFlow::PathNode source, DataFlow::PathNode sink
where McpSsrfFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This request depends on a user-provided MCP tool parameter."