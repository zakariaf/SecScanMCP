/**
 * @name Test Simple MCP Detection
 * @description Simple test to detect any exec usage in MCP context
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id js/test-mcp-simple
 * @tags security
 *       test
 */

import javascript

from DataFlow::CallNode call
where call.getCalleeName() = "exec"
select call, "Found exec call - potential command injection risk"