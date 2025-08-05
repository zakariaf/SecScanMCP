/**
 * @name SQL injection in MCP tool
 * @description An MCP tool parameter is used to construct a SQL query, which can allow
 *              attackers to execute arbitrary SQL commands and compromise the database.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id js/mcp-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import javascript
import semmle.javascript.security.dataflow.TaintTracking
import semmle.javascript.security.dataflow.SqlInjection

/**
 * A data flow source for SQL injection vulnerabilities in MCP servers.
 */
class McpToolParameterSource extends DataFlow::Node {
  McpToolParameterSource() {
    exists(Function f, Parameter p | this = DataFlow::parameterNode(p) and p.getFunction() = f |
      f instanceof Method and
      f.getDeclaringType().getName().regexpMatch("(?i).*(MCP|Mcp|Tool|Server).*") and
      f.getName().regexpMatch("(?i).*(tool|query|database|db).*")
    )
  }
}

/**
 * A configuration for taint tracking from MCP tool parameters to SQL execution sinks.
 */
module McpSqlInjectionConfig implements TaintTracking::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameterSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlInjection::Sink
  }
}

module McpSqlInjectionFlow = TaintTracking::Global<McpSqlInjectionConfig>;

from DataFlow::PathNode source, DataFlow::PathNode sink
where McpSqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on a user-provided MCP tool parameter."