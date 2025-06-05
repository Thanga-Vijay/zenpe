output "secret_arn" {
  description = "ARN of the MSG91 credentials secret"
  value       = aws_secretsmanager_secret.msg91_credentials.arn
}

output "policy_arn" {
  description = "ARN of the IAM policy for MSG91 access"
  value       = aws_iam_policy.msg91_access.arn
}

output "alarm_arn" {
  description = "ARN of the CloudWatch alarm for MSG91 failures"
  value       = aws_cloudwatch_metric_alarm.msg91_failures.arn
}
