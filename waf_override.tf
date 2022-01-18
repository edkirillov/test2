resource "azurerm_frontdoor_firewall_policy" "afd-waf" {
  custom_rule {
    name     = "noderce934013"
    enabled  = true
    priority = 100
    type     = "MatchRule"
    action   = "Block"

    match_condition {
      match_variable     = "RequestBody"
      operator           = "RegEx"
      negation_condition = false
      match_values       = ["(?:_(?:\\$\\$ND_FUNC\\$\\$_|_js_function)|(?:new\\s+Function|\\beval)\\s*\\(|String\\s*\\.\\s*fromCharCode|function\\s*\\(\\s*\\)\\s*{|module\\.exports\\s*=|this\\.constructor)"]
    }
  }

  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "1.1"

    //Cookies
    dynamic "exclusion" {
      for_each = ["okta-oauth-redirect-params", "x-csrf-token", "messages", "trifacta_browser_support", "okta-oauth-state", "okta-oauth-nonce", "_trifacta_session.sig", "ai_session"]
      content {
        match_variable = "RequestCookieNames"
        operator       = "Equals"
        selector       = exclusion.value
      }
    }

    //Query Arguments
    dynamic "exclusion" {
      for_each = ["uri", "dimension_filters", "test_url", "filter", "return_url", "scope"]
      content {
        match_variable = "QueryStringArgNames"
        operator       = "Equals"
        selector       = exclusion.value
      }
    }

    //Request Body Arguments
    dynamic "exclusion" {
      for_each = ["[logArgs][]", "[stack]", "message-url"]
      content {
        match_variable = "RequestBodyPostArgNames"
        operator       = "Contains"
        selector       = exclusion.value
      }
    }

    override {
      rule_group_name = "PHP"
      dynamic "rule" {
        for_each = ["933100", "933110", "933120", "933130", "933140", "933150", "933151", "933160", "933170", "933180"]
        content {
          rule_id = rule.value
          enabled = false
          action  = "Block"
        }
      }
    }

    override {
      rule_group_name = "LFI"
      rule {
        rule_id = "930110"
        action  = "Block"
        enabled = "false"
      }
    }

    override {
      rule_group_name = "JAVA"
      dynamic "rule" {
        for_each = ["944130", "944240"]
        content {
          rule_id = rule.value
          enabled = false
          action  = "Block"
        }
      }
    }

    //Dynamic
    override {
      rule_group_name = "XSS"
      dynamic "rule" {
        for_each = ["941320"]
        content {
          rule_id = rule.value
          enabled = false
          action  = "Block"
        }
      }
    }

    override {
      rule_group_name = "XSS"
      rule {
        rule_id = "941340"
        action  = "Block"
        enabled = "true"
        exclusion {
          match_variable = "RequestBodyPostArgNames"
          operator       = "Equals"
          selector       = "attachments"
        }
      }
    }

    override {
      rule_group_name = "SQLI"
      rule {
        rule_id = "942450"
        action  = "Block"
        enabled = "true"
        exclusion {
          match_variable = "RequestCookieNames"
          operator       = "Equals"
          selector       = "_ga"
        }
        exclusion {
          match_variable = "RequestBodyPostArgNames"
          operator       = "Equals"
          selector       = "SAMLResponse"
        }
      }
    }

    override {
      rule_group_name = "RFI"
      rule {
        rule_id = "931130"
        action  = "Block"
        enabled = "true"
        exclusion {
          match_variable = "QueryStringArgNames"
          operator       = "Equals"
          selector       = "iss"
        }
      }
    }
  }
}