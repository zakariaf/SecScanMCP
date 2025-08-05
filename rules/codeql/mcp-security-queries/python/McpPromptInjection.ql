/**
 * @name Prompt injection vulnerability in MCP tool
 * @description MCP tool descriptions or outputs may contain malicious prompts that could
 *              hijack the AI assistant's behavior when processing tool results.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id py/mcp-prompt-injection
 * @tags security
 *       external/cwe/cwe-352
 *       mcp
 *       ai-security
 */

import python
import semmle.python.dataflow.new.DataFlow

/**
 * Identifies MCP tool description definitions that might be vulnerable to prompt injection.
 */
class McpToolDescription extends DataFlow::Node {
  string description;
  
  McpToolDescription() {
    exists(Dict dict, KeyValuePair kvp |
      // Look for dictionary with 'description' key
      kvp = dict.getItem(_) and
      kvp.getKey().(StrConst).getText() = "description" and
      this.asCfgNode() = kvp.getValue() and
      // Ensure this is part of a tool definition
      exists(KeyValuePair sibling |
        sibling = dict.getItem(_) and
        sibling.getKey().(StrConst).getText() in ["name", "handler", "schema", "input_schema"]
      ) and
      // Get the description value if it's a string constant
      description = kvp.getValue().(StrConst).getText()
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
    exists(DataFlow::Node source |
      // Source is user input or external data
      (
        source = DataFlow::parameterNode(_) or
        exists(Attribute attr |
          source.asCfgNode() = attr and
          attr.getObject().(Name).getId() = "request" and
          attr.getName() in ["json", "data", "params", "args"]
        )
      ) and
      // There's flow to a tool description
      DataFlow::localFlow(source, this) and
      exists(Dict dict, KeyValuePair kvp |
        kvp = dict.getItem(_) and
        kvp.getKey().(StrConst).getText() = "description" and
        this.asCfgNode() = kvp.getValue()
      )
    )
  }
}

/**
 * Tool output that might contain prompt injection.
 */
class McpToolOutput extends DataFlow::Node {
  McpToolOutput() {
    exists(Return ret, Function f |
      ret.getScope() = f and
      this.asCfgNode() = ret.getValue() and
      // Function is an MCP tool handler
      exists(Decorator d |
        f.getADecorator() = d and
        d.getName() = "tool"
      )
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
  or
  (
    desc instanceof McpToolOutput and
    exists(StrConst s |
      s = desc.asCfgNode() and
      hasPromptInjectionPattern(s.getText())
    ) and
    message = "Tool output contains potential prompt injection pattern"
  )
select desc, message + " in MCP tool definition."