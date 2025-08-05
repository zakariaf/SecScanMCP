/**
 * @name MCP tool description loaded from an untrusted source
 * @description An MCP tool's description is derived from a non-static source, such as a
 *              file read or a network request. This is a significant risk for tool
 *              poisoning attacks, as the description is not auditable with the code.
 * @kind alert
 * @problem.severity warning
 * @security-severity 7.8
 * @precision medium
 * @id py/mcp-untrusted-tool-description
 * @tags security
 *       mcp
 *       tool-poisoning
 */

import python
import semmle.python.dataflow.new.DataFlow

// Define a source of data that is not a compile-time constant.
class NonStaticSource extends DataFlow::Node {
  NonStaticSource() {
    // A call to a function that reads from an external resource.
    exists(DataFlow::CallCfgNode call | this = call |
      // Common file reading functions
      call.getCallee().(AttrNode).getName() in ["read", "readline", "readlines", "load", "safe_load"]
      or
      // Common network request functions
      call.getCallee().(AttrNode).getName() in ["get", "post", "request", "json"]
    )
    or
    // A parameter to a function, which could be passed in at runtime.
    this instanceof DataFlow::ParameterNode
  }
}

// Define a sink as the 'description' argument in a tool's definition.
class McpToolDescriptionSink extends DataFlow::Node {
  McpToolDescriptionSink() {
    // The 'description' keyword argument in a tool decorator call.
    exists(Keyword k |
      k.getName() = "description" and
      this.asCfgNode() = k.getValue() and
      exists(Decorator d | k.getCall() = d.asCall() |
        d.asCall().getFunc().(Attribute).getName() = "tool" and
        d.asCall().getFunc().(Attribute).getObject().(Name).getId().regexpMatch("(?i).*(mcp|app|server)")
      )
    )
  }
}

from NonStaticSource source, McpToolDescriptionSink sink
where DataFlow::localFlow(source, sink)
select sink.asCfgNode(),
  "The description for this MCP tool is loaded from a dynamic source, creating a risk of tool poisoning."