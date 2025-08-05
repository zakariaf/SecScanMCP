/**
 * @name Data exfiltration risk in MCP tool
 * @description MCP tools that send data to external services without proper validation
 *              could be exploited to exfiltrate sensitive information.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id js/mcp-data-exfiltration
 * @tags security
 *       external/cwe/cwe-200
 *       mcp
 */

import javascript
import semmle.javascript.security.dataflow.RemoteFlowSources
import DataFlow::PathGraph

/**
 * Sensitive data sources in MCP context.
 */
class SensitiveDataSource extends DataFlow::Node {
  string dataType;
  
  SensitiveDataSource() {
    exists(DataFlow::PropRead pr |
      pr = this and
      (
        pr.getPropertyName().regexpMatch("(?i).*(password|secret|key|token|credential|private).*") and
        dataType = "credentials"
        or
        pr.getPropertyName().regexpMatch("(?i).*(ssn|social.?security|tax.?id|passport).*") and
        dataType = "PII"
        or
        pr.getPropertyName() = ["env", "process.env"] and
        dataType = "environment variables"
        or
        pr.getPropertyName().regexpMatch("(?i).*(database|db|sql).*") and
        dataType = "database content"
      )
    )
    or
    exists(DataFlow::CallNode call |
      call = this and
      (
        call.getCalleeName() = ["readFile", "readFileSync"] and
        call.getArgument(0).getStringValue().regexpMatch(".*\\.(key|pem|crt|p12|env)$") and
        dataType = "sensitive files"
        or
        call.getCalleeName().regexpMatch("(?i).*(query|select|find).*") and
        dataType = "database query results"
      )
    )
  }
  
  string getDataType() { result = dataType }
}

/**
 * External communication sinks that could exfiltrate data.
 */
class ExfiltrationSink extends DataFlow::Node {
  ExfiltrationSink() {
    exists(DataFlow::CallNode call |
      this = call.getAnArgument() and
      (
        // HTTP requests to external services
        call.getCalleeName() = ["fetch", "request", "post", "put", "axios"] or
        call = DataFlow::moduleImport(["node-fetch", "axios", "request", "got"]).getACall() or
        // WebSocket messages
        call.getCalleeName() = "send" and
        call.getReceiver().getALocalSource() instanceof DataFlow::NewNode and
        call.getReceiver().getALocalSource().(DataFlow::NewNode).getCalleeName() = "WebSocket" or
        // External API calls
        call.getReceiver().getALocalSource() = DataFlow::moduleImport(["@openai/api", "anthropic", "cohere"])
      )
    )
  }
}

/**
 * Configuration for tracking sensitive data to external sinks.
 */
class McpDataExfiltrationConfig extends TaintTracking::Configuration {
  McpDataExfiltrationConfig() { this = "McpDataExfiltrationConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof SensitiveDataSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ExfiltrationSink
  }
  
  override predicate isSanitizer(DataFlow::Node node) {
    // Redaction functions
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(redact|sanitize|clean|mask|filter).*") and
      node = call.getAnArgument()
    )
  }
  
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through object construction
    exists(DataFlow::ObjectLiteralNode obj |
      pred = obj.getAPropertyWrite().getRhs() and
      succ = obj
    )
    or
    // Track through array operations
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["concat", "push", "unshift"] and
      pred = call.getAnArgument() and
      succ = call
    )
  }
}

from McpDataExfiltrationConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink,
     SensitiveDataSource src
where 
  cfg.hasFlowPath(source, sink) and
  src = source.getNode()
select sink.getNode(), source, sink,
  "Potential exfiltration of " + src.getDataType() + " from $@.", 
  source.getNode(), "this source"