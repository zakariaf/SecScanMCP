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
 */

import javascript
import semmle.javascript.security.dataflow.TaintTracking
import semmle.javascript.security.dataflow.CodeInjection

/**
 * A data flow source for code injection vulnerabilities in MCP servers.
 * This class models any parameter of a method within a class that appears to be
 * an MCP server implementation.
 */
class McpToolParameterSource extends DataFlow::Node {
  McpToolParameterSource() {
    exists(Function f, Parameter p | this = DataFlow::parameterNode(p) and p.getFunction() = f |
      f instanceof Method and
      f.getDeclaringType().getName().regexpMatch("(?i).*(MCP|Mcp|Tool|Server).*") and
      f.getName().regexpMatch("(?i).*(tool|command|execute|run).*")
    )
  }
}

/**
 * A configuration for taint tracking from MCP tool parameters to code execution sinks.
 */
module McpCodeInjectionConfig implements TaintTracking::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameterSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof CodeInjection::Sink
  }
}

module McpCodeInjectionFlow = TaintTracking::Global<McpCodeInjectionConfig>;

from DataFlow::PathNode source, DataFlow::PathNode sink
where McpCodeInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This code depends on a user-provided MCP tool parameter."