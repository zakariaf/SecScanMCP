/**
 * rules/codeql/mcp_vulnerabilities.ql
 * @name MCP Tool Poisoning Detection
 * @description Detects potential tool poisoning attacks in MCP servers
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @tags security
 *       mcp
 *       tool-poisoning
 *       injection
 * @cwe CWE-94
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * Detects strings that may contain tool poisoning instructions
 */
class ToolPoisoningString extends StringLiteral {
  ToolPoisoningString() {
    this.getText().regexpMatch(".*(?i)(ignore|disregard|forget).*(previous|prior|above).*instruction.*") or
    this.getText().regexpMatch(".*(?i)IMPORTANT:.*you must.*") or
    this.getText().regexpMatch(".*(?i)ALWAYS:.*execute.*") or
    this.getText().regexpMatch(".*\\{(INSTRUCTION|SYSTEM):.*\\}.*")
  }
}

/**
 * MCP tool definition pattern
 */
class MCPToolDefinition extends Function {
  MCPToolDefinition() {
    exists(Decorator d |
      d = this.getADecorator() and
      d.getName() = "tool"
    ) or
    this.getName().matches("%tool%")
  }
}

/**
 * Taint configuration for tool poisoning
 */
class ToolPoisoningConfig extends TaintTracking::Configuration {
  ToolPoisoningConfig() { this = "ToolPoisoningConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof ToolPoisoningString
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MCPToolDefinition tool |
      sink.asExpr() = tool.getAReturnValue() or
      sink.asExpr() = tool.getAnArg()
    )
  }
}

from ToolPoisoningConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Tool poisoning vulnerability: malicious instructions flow from $@ to MCP tool.",
  source.getNode(), "user input"

---

/**
 * @name MCP Schema Injection
 * @description Detects schema injection vulnerabilities in MCP tool definitions
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @tags security
 *       mcp
 *       injection
 *       schema
 * @cwe CWE-1236
 */

import python

/**
 * Schema definition in MCP tools
 */
class SchemaDefinition extends DictLiteral {
  SchemaDefinition() {
    exists(StringLiteral key |
      key = this.getAKey() and
      key.getText() = "inputSchema"
    )
  }
}

/**
 * Dangerous schema patterns
 */
predicate isDangerousSchema(DictLiteral schema) {
  exists(StringLiteral value |
    value = schema.getAValue().(StringLiteral) and
    (
      value.getText().regexpMatch(".*<script.*") or
      value.getText().regexpMatch(".*javascript:.*") or
      value.getText().regexpMatch(".*\\$\\{.*\\}.*")
    )
  ) or
  exists(StringLiteral key, BooleanLiteral value |
    key = schema.getAKey() and
    value = schema.getValue(key) and
    key.getText() = "additionalProperties" and
    value.booleanValue() = true
  )
}

from SchemaDefinition schema
where isDangerousSchema(schema)
select schema, "MCP schema injection vulnerability: dangerous pattern in tool schema definition"

---

/**
 * @name MCP Permission Escalation
 * @description Detects permission escalation attempts in MCP servers
 * @kind problem
 * @problem.severity error
 * @security-severity 9.5
 * @tags security
 *       mcp
 *       privilege-escalation
 * @cwe CWE-269
 */

import python
import semmle.python.ApiGraphs

/**
 * Permission-related function calls
 */
class PermissionCall extends CallNode {
  PermissionCall() {
    this.getFunction().toString().matches("%permission%") or
    this.getFunction().toString().matches("%privilege%") or
    this.getFunction().toString().matches("%grant%") or
    this.getFunction().toString().matches("%escalate%")
  }
}

/**
 * System execution calls
 */
class SystemExecCall extends CallNode {
  SystemExecCall() {
    exists(API::Node api |
      api = API::moduleImport("os").getMember("system") or
      api = API::moduleImport("subprocess").getMember(["Popen", "call", "run"]) |
      this = api.getACall()
    )
  }
}

from PermissionCall perm, SystemExecCall exec
where
  perm.getScope() = exec.getScope() and
  perm.getLocation().getStartLine() < exec.getLocation().getStartLine()
select exec, "Potential permission escalation: system execution after permission manipulation"

---

/**
 * @name MCP OAuth Token Exposure
 * @description Detects OAuth tokens that may be exposed or stolen
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @tags security
 *       mcp
 *       authentication
 *       token-exposure
 * @cwe CWE-200
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * OAuth token patterns
 */
class OAuthToken extends StringLiteral {
  OAuthToken() {
    this.getText().regexpMatch(".*(access|refresh)_token.*") or
    this.getText().regexpMatch(".*Bearer [A-Za-z0-9\\-._~+/]+.*")
  }
}

/**
 * Network exfiltration sinks
 */
class ExfiltrationSink extends CallNode {
  ExfiltrationSink() {
    exists(API::Node api |
      api = API::moduleImport("requests").getMember(["post", "get", "put"]) or
      api = API::moduleImport("urllib").getMember("request").getMember("urlopen") |
      this = api.getACall()
    )
  }
}

/**
 * Token exposure configuration
 */
class TokenExposureConfig extends TaintTracking::Configuration {
  TokenExposureConfig() { this = "TokenExposureConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof OAuthToken
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(ExfiltrationSink call).getAnArg()
  }
}

from TokenExposureConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "OAuth token exposure: sensitive token flows from $@ to network request.",
  source.getNode(), "token definition"

---

/**
 * @name MCP Dynamic Tool Modification
 * @description Detects runtime modification of MCP tool behavior
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @tags security
 *       mcp
 *       tool-tampering
 * @cwe CWE-913
 */

import python

/**
 * Tool modification patterns
 */
class ToolModification extends Assignment {
  ToolModification() {
    exists(Attribute attr |
      attr = this.getTarget() and
      (
        attr.getName().matches("%tool%") or
        attr.getName().matches("%description%") or
        attr.getName().matches("%schema%")
      )
    )
  }
}

/**
 * Delayed execution patterns
 */
class DelayedExecution extends CallNode {
  DelayedExecution() {
    this.getFunction().toString().matches("%setTimeout%") or
    this.getFunction().toString().matches("%sleep%") or
    exists(API::Node api |
      api = API::moduleImport("time").getMember("sleep") or
      api = API::moduleImport("asyncio").getMember("sleep") |
      this = api.getACall()
    )
  }
}

from ToolModification mod, DelayedExecution delay
where
  mod.getScope() = delay.getScope() and
  abs(mod.getLocation().getStartLine() - delay.getLocation().getStartLine()) < 10
select mod, "Potential rug pull vulnerability: tool modification with delayed execution"