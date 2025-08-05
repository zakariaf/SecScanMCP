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
 *       mcp
 */

import javascript
import semmle.javascript.security.dataflow.ServerSideRequestForgery
import DataFlow::PathGraph

/**
 * A data flow source for SSRF vulnerabilities in MCP servers.
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
 * Configuration for tracking SSRF from MCP inputs.
 */
class McpSsrfConfig extends TaintTracking::Configuration {
  McpSsrfConfig() { this = "McpSsrfConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof McpToolParameterSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ServerSideRequestForgery::Sink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // URL validation
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(validate|check|verify).*url.*") and
      node = call.getAnArgument()
    )
    or
    // Allowlist checking
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(isAllowed|checkAllowlist|isWhitelisted).*") and
      node = call.getAnArgument()
    )
  }
  
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through URL construction
    exists(DataFlow::NewNode urlConstructor |
      urlConstructor.getCalleeName() = "URL" and
      pred = urlConstructor.getArgument(0) and
      succ = urlConstructor
    )
    or
    // Track through string concatenation for URLs
    exists(DataFlow::CallNode concat |
      concat.getCalleeName() = "concat" and
      concat.getReceiver().getStringValue().regexpMatch("^https?://.*") and
      pred = concat.getAnArgument() and
      succ = concat
    )
  }
}

from McpSsrfConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SSRF vulnerability: request URL depends on MCP tool parameter from $@.",
  source.getNode(), "here"