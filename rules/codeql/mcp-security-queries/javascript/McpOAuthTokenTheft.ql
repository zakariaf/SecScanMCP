/**
 * @name OAuth token exposure in MCP server
 * @description MCP servers storing OAuth tokens insecurely can lead to token theft
 *              if the server is compromised.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id js/mcp-oauth-token-theft
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-522
 *       mcp
 */

import javascript

/**
 * Identifies OAuth token storage patterns in MCP servers.
 */
class OAuthTokenStorage extends DataFlow::Node {
  OAuthTokenStorage() {
    exists(DataFlow::PropWrite pw |
      pw.getPropertyName().regexpMatch("(?i).*(token|oauth|access_token|refresh_token|api_key|secret).*") and
      this = pw.getRhs() and
      // Exclude test files and mocks
      not pw.getFile().getRelativePath().regexpMatch(".*(test|spec|mock).*")
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
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["writeFile", "writeFileSync", "appendFile", "appendFileSync"] and
      DataFlow::localFlow(this, call.getArgument(1))
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
      DataFlow::localFlow(this, DataFlow::valueNode(gv.getAnAssignedExpr()))
    )
  }
  
  override string getReason() { result = "Token stored in global variable" }
}

/**
 * Tokens logged to console or files.
 */
class LoggedTokenStorage extends InsecureTokenStorage {
  LoggedTokenStorage() {
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(log|debug|info|warn|error|trace).*") and
      DataFlow::localFlow(this, call.getAnArgument())
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
    not exists(DataFlow::CallNode encCall |
      encCall.getCalleeName().regexpMatch("(?i).*(encrypt|cipher|hash|crypto).*") and
      encCall.getContainer() = this.getContainer()
    ) and
    // Not using a secure storage library
    not exists(DataFlow::ModuleImportNode imp |
      imp.getPath().regexpMatch(".*(keytar|keychain|credential|secure-store).*") and
      imp.getFile() = this.getFile()
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
    exists(DataFlow::Node token, DataFlow::CallNode call |
      token instanceof OAuthTokenStorage and
      (
        // HTTP without HTTPS
        call.getCalleeName() = ["request", "get", "post"] and
        exists(string url |
          url = call.getArgument(0).getStringValue() and
          url.regexpMatch("^http://.*")
        ) and
        DataFlow::localFlow(token, call.getAnArgument()) and
        reason = "Token transmitted over insecure HTTP"
      )
      or
      (
        // Token in URL parameters
        call.getCalleeName().regexpMatch("(?i).*(url|uri|endpoint).*") and
        DataFlow::localFlow(token, call.getAnArgument()) and
        reason = "Token exposed in URL parameters"
      )
    )
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