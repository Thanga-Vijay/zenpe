# AWS Shield Advanced (Optional - requires subscription)
resource "aws_shield_protection" "alb" {
  count = var.enable_shield_advanced ? 1 : 0
  
  name         = "${var.app_name}-alb-protection-${var.environment}"
  resource_arn = var.alb_arn
  
  tags = {
    Name        = "${var.app_name}-shield-protection"
    Environment = var.environment
  }
}

resource "aws_shield_protection" "api_gateway" {
  count = var.enable_shield_advanced && var.api_gateway_arn != "" ? 1 : 0
  
  name         = "${var.app_name}-api-gateway-protection-${var.environment}"
  resource_arn = var.api_gateway_arn
  
  tags = {
    Name        = "${var.app_name}-api-gateway-shield-protection"
    Environment = var.environment
  }
}

# AWS WAF WebACL
resource "aws_wafv2_web_acl" "main" {
  name        = "${var.app_name}-web-acl-${var.environment}"
  description = "WAF Web ACL for ${var.app_name}"
  scope       = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  # AWS Managed rules
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 1
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWS-AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }
  
  # SQL Injection Protection
  rule {
    name     = "AWS-AWSManagedRulesSQLiRuleSet"
    priority = 2
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWS-AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }
  
  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 3
    
    action {
      block {}
    }
    
    statement {
      rate_based_statement {
        limit              = 3000
        aggregate_key_type = "IP"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }
  
  # Geo restriction rule (optional)
  dynamic "rule" {
    for_each = length(var.geo_restriction_countries) > 0 ? [1] : []
    content {
      name     = "GeoRestrictionRule"
      priority = 4
      
      action {
        block {}
      }
      
      statement {
        geo_match_statement {
          country_codes = var.geo_restriction_countries
        }
      }
      
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "GeoRestrictionRule"
        sampled_requests_enabled   = true
      }
    }
  }
  
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.app_name}-web-acl-${var.environment}"
    sampled_requests_enabled   = true
  }
  
  tags = {
    Name        = "${var.app_name}-web-acl"
    Environment = var.environment
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# Associate WAF with API Gateway (if provided)
resource "aws_wafv2_web_acl_association" "api_gateway" {
  count = var.api_gateway_arn != "" ? 1 : 0
  
  resource_arn = var.api_gateway_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# Security group for common access
resource "aws_security_group" "common" {
  name        = "${var.app_name}-common-sg-${var.environment}"
  description = "Common security group for ${var.app_name}"
  vpc_id      = var.vpc_id
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.app_name}-common-sg"
    Environment = var.environment
  }
}

# Enable GuardDuty (if requested)
resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0
  
  enable = true
  
  tags = {
    Name        = "${var.app_name}-guardduty"
    Environment = var.environment
  }
}

# IP Whitelisting for Admin Access
resource "aws_security_group_rule" "kyc_admin_whitelist" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = var.admin_whitelisted_ips
  security_group_id = var.kyc_service_security_group_id
  description       = "KYC Admin Access"
}

