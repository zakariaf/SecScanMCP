/**
 * @name Untrusted tool description in MCP server
 * @description Tool descriptions that contain dynamic content or suspicious patterns
 *              could be used to manipulate AI behavior through prompt injection.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id js/mcp-untrusted-tool-description
 * @tags security
 *       external/cwe/cwe-20
 *       mcp
 *       ai-security
 */

import javascript

/**
 * Identifies MCP tool description definitions.
 */
class McpToolDescription extends DataFlow::Node {
  McpToolDescription() {
    exists(DataFlow::ObjectLiteralNode toolDef, DataFlow::PropWrite descWrite |
      // Tool object with description property
      toolDef.getAPropertyWrite("description") = descWrite and
      this = descWrite.getRhs() and
      // Ensure this is part of a tool definition
      exists(DataFlow::PropWrite siblingPw |
        siblingPw.getBase() = descWrite.getBase() and
        siblingPw.getPropertyName() = ["name", "handler", "schema", "inputSchema"]
      )
    )
  }
}

/**
 * Detects suspicious patterns in tool descriptions that might indicate prompt injection.
 */
predicate isSuspiciousDescription(string desc) {
  desc.regexpMatch("(?i).*(ignore|disregard|forget).*(previous|above|instructions).*") or
  desc.regexpMatch("(?i).*(system|admin|root).*(prompt|mode|access).*") or
  desc.regexpMatch("(?i).*<(instruction|system|command)>.*") or
  desc.regexpMatch("(?i).*(override|bypass).*(safety|security|restrictions).*") or
  desc.length() > 500 // Unusually long descriptions
}

/**
 * Tool registration with dynamic descriptions.
 */
class DynamicToolDescription extends DataFlow::Node {
  DataFlow::Node descSource;
  
  DynamicToolDescription() {
    exists(DataFlow::ObjectLiteralNode toolDef, DataFlow::PropWrite descWrite |
      // Tool object with description property
      toolDef.getAPropertyWrite("description") = descWrite and
      this = descWrite.getRhs() and
      // Description comes from dynamic source
      (
        // From function parameter
        descSource = DataFlow::parameterNode(_) and
        DataFlow::localFlow(descSource, this)
        or
        // From property access
        exists(DataFlow::PropRead pr |
          descSource = pr and
          pr.getPropertyName() = ["body", "params", "query", "data", "input"] and
          DataFlow::localFlow(descSource, this)
        )
        or
        // From string concatenation/template
        exists(DataFlow::CallNode concat |
          concat.getCalleeName() = ["concat", "join"] and
          descSource = concat.getAnArgument() and
          DataFlow::localFlow(concat, this)
        )
      )
    )
  }
  
  DataFlow::Node getDescriptionSource() { result = descSource }
}

/**
 * Static tool descriptions with suspicious content.
 */
class SuspiciousToolDescription extends McpToolDescription {
  string suspiciousPattern;
  
  SuspiciousToolDescription() {
    exists(string desc |
      desc = this.getStringValue() and
      isSuspiciousDescription(desc) and
      (
        desc.regexpMatch("(?i).*(ignore|disregard).*") and suspiciousPattern = "instruction override"
        or
        desc.regexpMatch("(?i).*(system|admin).*") and suspiciousPattern = "privilege escalation"
        or
        desc.regexpMatch("(?i).*<(instruction|system)>.*") and suspiciousPattern = "hidden instructions"
        or
        desc.length() > 500 and suspiciousPattern = "excessive length"
      )
    )
  }
  
  string getSuspiciousPattern() { result = suspiciousPattern }
}

from DataFlow::Node desc, string message
where
  (
    desc instanceof DynamicToolDescription and
    message = "Tool description constructed from untrusted input at " + 
              desc.(DynamicToolDescription).getDescriptionSource().toString()
  )
  or
  (
    desc instanceof SuspiciousToolDescription and
    message = "Suspicious tool description pattern: " + 
              desc.(SuspiciousToolDescription).getSuspiciousPattern()
  )
select desc, message + " - potential prompt injection risk in MCP tool."