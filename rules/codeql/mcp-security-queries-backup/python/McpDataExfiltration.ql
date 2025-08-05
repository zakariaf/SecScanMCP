/**
 * @name Potential data exfiltration in MCP tool
 * @description An MCP tool accesses a sensitive data source (e.g., environment variable)
 *              and also makes a network request, which could be used to exfiltrate the data.
 * @kind path-problem
 * @problem.severity high
 * @security-severity 8.2
 * @precision medium
 * @id py/mcp-data-exfiltration
 * @tags security
 *       mcp
 *       exfiltration
 *       external/cwe/cwe-200
 */

import python
import semmle.python.security.dataflow.ServerSideRequestForgery
import semmle.python.dataflow.new.DataFlow

// Define a source of sensitive information.
class SensitiveDataSource extends DataFlow::Node {
  SensitiveDataSource() {
    // Reading an environment variable.
    exists(DataFlow::CallCfgNode call | this = call |
      call.getCallee().(AttrNode).getObject().(Name).getId() = "os" and
      call.getCallee().(AttrNode).getName() = "environ"
    )
    or
    // Reading a potentially sensitive file.
    exists(DataFlow::CallCfgNode call, StringLiteral path |
      this = call and
      call.getArg(0).getNode().asExpr() = path and
      path.getText().regexpMatch("(?i).*(\\.env|config|secret|passwd|shadow|key|token).*") and
      call.getCalleeName() = "open"
    )
  }
}

// Define a configuration that tracks the flow from sensitive data to a network sink.
module McpExfiltrationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof SensitiveDataSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof ServerSideRequestForgery::Sink
  }
}

module McpExfiltrationFlow = TaintTracking::Global<McpExfiltrationConfig>;

// Helper to identify the function containing a data flow node.
Function getEnclosingMcpTool(DataFlow::Node node) {
  exists(Decorator d |
    result = node.getEnclosingFunction() and
    result.getAdecorator() = d and
    d.asCall().getFunc().(Attribute).getName() = "tool"
  )
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  McpExfiltrationFlow::flowPath(source, sink) and
  // Crucially, ensure the source and sink are within the *same* MCP tool function.
  getEnclosingMcpTool(source.getNode()) = getEnclosingMcpTool(sink.getNode())
select sink.getNode(), source, sink,
  "This network request may exfiltrate sensitive data read from " + source.getNode().toString() + "."