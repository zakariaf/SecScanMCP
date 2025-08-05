/**
 * @name Path traversal in MCP tool
 * @description An MCP tool parameter is used to construct a file path, which can allow
 *              attackers to access arbitrary files on the server's file system.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id js/mcp-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 */

import javascript
import semmle.javascript.security.dataflow.TaintTracking
import semmle.javascript.security.dataflow.PathInjection

/**
 * A data flow source for path traversal vulnerabilities in MCP servers.
 */
class McpToolParameterSource extends DataFlow::Node {
  McpToolParameterSource() {
    exists(Function f, Parameter p | this = DataFlow::parameterNode(p) and p.getFunction() = f |
      f instanceof Method and
      f.getDeclaringType().getName().regexpMatch("(?i).*(MCP|Mcp|Tool|Server).*") and
      f.getName().regexpMatch("(?i).*(tool|file|path|read|write).*")
    )
  }
}

/**
 * A configuration for taint tracking from MCP tool parameters to file system sinks.
 */
module McpPathTraversalConfig implements TaintTracking::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameterSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof PathInjection::Sink
  }
}

module McpPathTraversalFlow = TaintTracking::Global<McpPathTraversalConfig>;

from DataFlow::PathNode source, DataFlow::PathNode sink
where McpPathTraversalFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This file path depends on a user-provided MCP tool parameter."