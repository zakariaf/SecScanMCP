/**
 * @name MCP tool parameter remote flow sources
 * @description Identifies MCP tool parameters as sources of remote user input
 * @kind library
 */

import javascript
import semmle.javascript.security.dataflow.RemoteFlowSources

/**
 * A parameter in an MCP tool handler function
 */
class MCPToolParameter extends RemoteFlowSource::Range {
  MCPToolParameter() {
    exists(Function f |
      // Match MCP server patterns
      (
        // Tool handler methods
        f.getName().regexpMatch("(?i)(handle|execute|run|process).*tool.*") or
        // MCP server files
        f.getFile().getBaseName().regexpMatch("(?i).*mcp.*server.*") or
        // Common MCP parameter names
        exists(Parameter p | p = f.getAParameter() |
          p.getName().regexpMatch("(?i)(params|args|arguments|input|data|payload)")
        )
      ) and
      // This is a parameter node
      this = DataFlow::parameterNode(f.getAParameter())
    )
  }

  override string getSourceType() {
    result = "MCP tool parameter"
  }
}