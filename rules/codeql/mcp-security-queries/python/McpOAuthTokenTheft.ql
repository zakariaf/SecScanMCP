/**
 * @name OAuth token exposure in MCP server
 * @description MCP servers storing OAuth tokens insecurely can lead to token theft
 *              if the server is compromised.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id py/mcp-oauth-token-theft
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-522
 *       mcp
 */

import python
import semmle.python.dataflow.new.DataFlow

/**
 * Identifies OAuth token storage patterns in MCP servers.
 */
class OAuthTokenStorage extends DataFlow::Node {
  OAuthTokenStorage() {
    exists(AssignStmt assign |
      this.asCfgNode() = assign.getValue() and
      assign.getTarget().(Name).getId().regexpMatch("(?i).*(token|oauth|access_token|refresh_token|api_key|secret).*") and
      // Exclude test files
      not assign.getLocation().getFile().getRelativePath().regexpMatch(".*(test|spec|mock).*")
    )
  }
}

/**
 * Identifies insecure token storage patterns.
 */
abstract class InsecureTokenStorage extends OAuthTokenStorage {
  abstract string getReason();
}

/**
 * Tokens stored in plain text files.
 */
class PlainFileTokenStorage extends InsecureTokenStorage {
  PlainFileTokenStorage() {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asCfgNode().(AttrNode).getName() in ["write", "writelines"] and
      DataFlow::localFlow(this, call.getArg(0))
    )
    or
    exists(DataFlow::CallCfgNode call |
      call.getFunction().asCfgNode().(NameNode).getId() = "open" and
      call.getArgByName("mode").asCfgNode().(StrConst).getText().matches("%w%") and
      exists(DataFlow::AttrRead write |
        write.getObject() = call and
        write.getAttributeName() = "write" and
        DataFlow::localFlow(this, write.getACall().getArg(0))
      )
    )
  }
  
  override string getReason() { result = "Token stored in plain text file" }
}

/**
 * Tokens stored in global variables.
 */
class GlobalTokenStorage extends InsecureTokenStorage {
  GlobalTokenStorage() {
    exists(GlobalVariable gv |
      DataFlow::localFlow(this, DataFlow::exprNode(gv.getAnAssignedValue()))
    )
  }
  
  override string getReason() { result = "Token stored in global variable" }
}

/**
 * Tokens logged to console or files.
 */
class LoggedTokenStorage extends InsecureTokenStorage {
  LoggedTokenStorage() {
    exists(DataFlow::CallCfgNode call |
      (
        // Logging functions
        call.getFunction().asCfgNode().(AttrNode).getName() in ["debug", "info", "warning", "error", "critical"] and
        call.getFunction().asCfgNode().(AttrNode).getObject().(NameNode).getId() in ["logger", "logging", "log"]
        or
        // Print function
        call.getFunction().asCfgNode().(NameNode).getId() = "print"
      ) and
      DataFlow::localFlow(this, call.getAnArg())
    )
  }
  
  override string getReason() { result = "Token logged to console or log files" }
}

/**
 * Tokens stored without encryption.
 */
class UnencryptedTokenStorage extends InsecureTokenStorage {
  UnencryptedTokenStorage() {
    // Token is stored but no encryption call is nearby
    not exists(DataFlow::CallCfgNode encCall |
      encCall.getFunction().asCfgNode().(AttrNode).getName().regexpMatch("(?i).*(encrypt|cipher|hash).*") and
      encCall.getScope() = this.getScope()
    ) and
    // Not using a secure storage library
    not exists(Import imp |
      imp.getAName().regexpMatch(".*(keyring|cryptography|secrets).*") and
      imp.getScope() = this.getScope().getScope()
    )
  }
  
  override string getReason() { result = "Token stored without encryption" }
}

/**
 * Identifies token transmission without proper security.
 */
class InsecureTokenTransmission extends DataFlow::Node {
  string reason;
  
  InsecureTokenTransmission() {
    exists(DataFlow::Node token, DataFlow::CallCfgNode call |
      token instanceof OAuthTokenStorage and
      (
        // HTTP without HTTPS
        call.getFunction().asCfgNode().(AttrNode).getName() in ["get", "post", "put", "request"] and
        exists(StrConst url |
          url = call.getArg(0).asCfgNode() and
          url.getText().regexpMatch("^http://.*")
        ) and
        DataFlow::localFlow(token, call.getAnArg()) and
        reason = "Token transmitted over insecure HTTP"
      )
      or
      (
        // Token in URL parameters
        exists(BinaryExpr concat |
          concat.getOp() instanceof Add and
          concat.getAnOperand().(StrConst).getText().matches("%?%") and
          DataFlow::localFlow(token, DataFlow::exprNode(concat.getAnOperand()))
        ) and
        reason = "Token exposed in URL parameters"
      )
    ) and
    this = token
  }
  
  string getReason() { result = reason }
}

from DataFlow::Node node, string message
where
  (
    node instanceof InsecureTokenStorage and
    message = node.(InsecureTokenStorage).getReason()
  )
  or
  (
    node instanceof InsecureTokenTransmission and
    message = node.(InsecureTokenTransmission).getReason()
  )
select node, message + " in MCP server implementation."