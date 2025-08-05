/**
 * @name SQL injection in MCP tool
 * @description An MCP tool parameter is used to construct a SQL query, which can allow
 *              attackers to execute arbitrary SQL commands and compromise the database.
 *              This pattern was observed in a real-world MCP server vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/mcp-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.security.dataflow.SqlInjection

/**
 * A data flow source for SQL injection vulnerabilities in MCP servers.
 */
class McpToolParameterSource extends SqlInjection::Source {
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
 * A configuration for taint tracking from MCP tool parameters to SQL execution sinks.
 */
class McpSqlInjectionConfig extends SqlInjection::Configuration {
  McpSqlInjectionConfig() { this = "McpSqlInjectionConfig" }

  override predicate isSource(SqlInjection::Source source) {
    source instanceof McpToolParameterSource
  }
}

from McpSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on a user-provided MCP tool parameter."