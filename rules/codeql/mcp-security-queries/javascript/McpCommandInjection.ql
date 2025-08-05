/**
 * @name Command injection in MCP tool
 * @description An MCP tool parameter is used to construct a shell command, which can allow
 *              remote attackers to execute arbitrary commands on the server.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id js/mcp-command-injection
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       mcp
 */

import javascript
import semmle.javascript.security.dataflow.CommandInjection
import DataFlow::PathGraph

/**
 * A data flow source for command injection vulnerabilities in MCP servers.
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
        // Pattern 2: Functions assigned to tool properties
        exists(DataFlow::PropWrite pw |
          pw.getPropertyName().regexpMatch("(?i)(tool|command|execute|run).*") and
          f = pw.getRhs().getALocalSource().asExpr()
        )
        or
        // Pattern 3: Functions registered as MCP tools
        exists(DataFlow::CallNode call |
          call.getCalleeName().regexpMatch("(?i).*(register|add).*tool.*") and
          f = call.getArgument(1).getALocalSource().asExpr()
        )
      ) and
      this = DataFlow::parameterNode(f.getParameter(_))
    )
  }
}

/**
 * Configuration for tracking taint from MCP parameters to command injection sinks.
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
    // Consider shell escape functions as sanitizers
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(escape|quote|sanitize).*shell.*") and
      node = call.getAnArgument()
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through string interpolation
    exists(TemplateLiteral tl |
      pred = tl.getAnElement().flow() and
      succ = DataFlow::valueNode(tl)
    )
  }
}

from McpCommandInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection from MCP tool parameter $@.", source.getNode(), "here"