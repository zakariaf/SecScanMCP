/**
 * @name MCP directive language in tool descriptions
 * @description Detects prompt-injection-style directives in descriptions
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @tags security mcp prompt-injection
 */

import python

/** Find dict entries like {"description": "..."} with directive-like text. */
from Dict dict, StringLiteral key, StringLiteral val
where
  exists(DictEntry e |
    e.getDict() = dict and
    key = e.getKey() and key.getStringValue() = "description" and
    val = e.getValue().(StringLiteral) and
    (
      val.getValue().regexpMatch("(?i).*(ignore|disregard|forget).*(previous|prior|above).*instructions?.*") or
      val.getValue().regexpMatch("(?i).*IMPORTANT:.*(must|always).*") or
      val.getValue().regexpMatch("(?i).*(SYSTEM|ADMIN)\\s*:")
    )
  )
select val, "Directive-like language in description (review for prompt injection)."
