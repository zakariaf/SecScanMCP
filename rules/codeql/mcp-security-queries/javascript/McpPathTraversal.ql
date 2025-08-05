/**
 * @name Path traversal in MCP tool
 * @description An MCP tool parameter is used to access files without proper validation,
 *              potentially allowing attackers to access arbitrary files.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.6
 * @precision high
 * @id js/mcp-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       mcp
 */

import javascript
import semmle.javascript.security.dataflow.TaintedPath
import DataFlow::PathGraph

/**
 * A data flow source for path traversal vulnerabilities in MCP servers.
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
 * Configuration for tracking path traversal from MCP inputs.
 */
class McpPathTraversalConfig extends TaintTracking::Configuration {
  McpPathTraversalConfig() { this = "McpPathTraversalConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameterSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof TaintedPath::Sink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // Path validation functions
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(normalize|resolve|isAbsolute|validate).*path.*") and
      node = call.getAnArgument()
    )
    or
    // Basename extraction (removes directory traversal)
    exists(DataFlow::ModuleImportNode path |
      path.getPath() = "path" and
      node = path.getAMemberCall("basename").getArgument(0)
    )
  }
  
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through path.join operations
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleMember("path", "join").getACall() and
      pred = call.getAnArgument() and
      succ = call
    )
  }
}

from McpPathTraversalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Path traversal vulnerability: file path depends on MCP tool parameter from $@.",
  source.getNode(), "here"