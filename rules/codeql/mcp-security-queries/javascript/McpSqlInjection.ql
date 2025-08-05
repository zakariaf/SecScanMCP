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
 *       mcp
 */

import javascript
import semmle.javascript.security.dataflow.SqlInjection
import DataFlow::PathGraph

/**
 * A data flow source for SQL injection vulnerabilities in MCP servers.
 */
class McpToolParameterSource extends DataFlow::Node {
  McpToolParameterSource() {
    exists(Function f |
      // Match functions that are MCP tool handlers
      (
        // Pattern 1: Methods in MCP-related classes
        f instanceof Method and
        f.getDeclaringType().getName().regexpMatch("(?i).*(MCP|Mcp|Tool|Server).*") and
        f.getName().regexpMatch("(?i).*(tool|command|execute|run|handle).*")
        or
        // Pattern 2: Functions with MCP-related decorators (TypeScript)
        exists(Decorator d |
          f.getADecorator() = d and
          d.getDecoratorName().regexpMatch("(?i).*(mcp|tool).*")
        )
        or
        // Pattern 3: Tool handler functions in MCP server implementations
        exists(DataFlow::PropWrite pw |
          pw.getPropertyName() = "tools" and
          pw.getRhs().getALocalSource().asExpr().(ObjectExpr).getAProperty().getInit() = f
        )
      ) and
      this = DataFlow::parameterNode(f.getParameter(_))
    )
  }
}

/**
 * Configuration for tracking SQL injection from MCP inputs.
 */
class McpSqlInjectionConfig extends TaintTracking::Configuration {
  McpSqlInjectionConfig() { this = "McpSqlInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameterSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlInjection::Sink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // Parameterized query preparation
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["prepare", "prepareStatement"] and
      node = call.getAnArgument()
    )
    or
    // SQL escape functions
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(escape|quote|sanitize).*sql.*") and
      node = call.getAnArgument()
    )
  }
  
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through string template literals
    exists(TemplateLiteral tl |
      pred = tl.getAnElement().flow() and
      succ = DataFlow::valueNode(tl)
    )
    or
    // Track through query builders
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["where", "select", "from", "join", "orderBy"] and
      pred = call.getAnArgument() and
      succ = call
    )
  }
}

from McpSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection vulnerability: query depends on MCP tool parameter from $@.",
  source.getNode(), "here"