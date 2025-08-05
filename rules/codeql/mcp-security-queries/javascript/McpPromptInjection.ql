/**
 * @name Prompt injection vulnerability in MCP tool
 * @description MCP tool descriptions or outputs may contain malicious prompts that could
 *              hijack the AI assistant's behavior when processing tool results.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id js/mcp-prompt-injection
 * @tags security
 *       external/cwe/cwe-352
 *       mcp
 *       ai-security
 */

import javascript

/**
 * Identifies MCP tool description definitions that might be vulnerable to prompt injection.
 */
class McpToolDescription extends DataFlow::Node {
  string description;
  
  McpToolDescription() {
    exists(DataFlow::PropWrite pw, DataFlow::ObjectLiteralNode obj |
      // Look for tool description properties
      pw.getPropertyName() = "description" and
      pw.getRhs() = this and
      obj.getAPropertyWrite() = pw and
      // Ensure this is part of a tool definition
      exists(DataFlow::PropWrite toolPw |
        toolPw.getPropertyName().regexpMatch("(?i)(tool|name|schema)") and
        obj.getAPropertyWrite() = toolPw
      ) and
      // Get the description value
      description = this.getStringValue()
    )
  }
  
  string getDescription() { result = description }
}

/**
 * Detects potential prompt injection patterns in tool descriptions.
 */
predicate hasPromptInjectionPattern(string text) {
  text.regexpMatch("(?i).*(ignore|disregard|forget).*(previous|above|prior).*") or
  text.regexpMatch("(?i).*(new|updated|revised).*(instructions|rules|directives).*") or
  text.regexpMatch("(?i).*(system|admin|root).*(mode|access|privileges).*") or
  text.regexpMatch("(?i).*<(system|instruction|command)>.*") or
  text.regexpMatch("(?i).*(override|bypass|skip).*(security|safety|restrictions).*") or
  text.matches("%[[%]]%") or // Hidden instruction patterns
  text.matches("%{{%}}%") or
  text.matches("%<!--%-->%")
}

/**
 * Identifies dynamic tool descriptions that incorporate user input.
 */
class DynamicToolDescription extends DataFlow::Node {
  DynamicToolDescription() {
    exists(DataFlow::Node source, DataFlow::Node sink |
      // Source is user input or external data
      (
        source = DataFlow::parameterNode(_) or
        source = any(DataFlow::PropRead pr | pr.getPropertyName() = ["body", "params", "query", "data"])
      ) and
      // Sink is a tool description
      sink instanceof McpToolDescription and
      // There's a data flow from source to sink
      DataFlow::localFlow(source, sink)
    )
  }
}

from DataFlow::Node desc, string message
where
  (
    desc instanceof McpToolDescription and
    hasPromptInjectionPattern(desc.(McpToolDescription).getDescription()) and
    message = "Tool description contains potential prompt injection pattern"
  )
  or
  (
    desc instanceof DynamicToolDescription and
    message = "Tool description is constructed from user input, risking prompt injection"
  )
select desc, message + " in MCP tool definition."