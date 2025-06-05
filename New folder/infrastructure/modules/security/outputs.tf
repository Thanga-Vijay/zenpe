output "web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.id
}

output "common_security_group_id" {
  description = "ID of the common security group"
  value       = aws_security_group.common.id
}

output "shield_protection_id" {
  description = "ID of the Shield Advanced protection"
  value       = var.enable_shield_advanced ? aws_shield_protection.alb[0].id : null
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : null
}
