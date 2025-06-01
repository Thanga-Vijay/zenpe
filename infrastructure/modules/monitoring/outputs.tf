output "log_group_names" {
  description = "Names of the CloudWatch log groups"
  value = {
    ecs         = aws_cloudwatch_log_group.ecs.name
    api_gateway = aws_cloudwatch_log_group.api_gateway.name
    rds         = aws_cloudwatch_log_group.rds.name
  }
}

output "dashboard_name" {
  description = "Name of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "alarm_topic_arn" {
  description = "ARN of the SNS topic for alarms"
  value       = aws_sns_topic.alarms.arn
}

output "alarm_topic_name" {
  description = "Name of the SNS topic for alarms"
  value       = aws_sns_topic.alarms.name
}

# output "lambda_function_arn" {
#   description = "ARN of the Lambda function for Slack notifications"
#   value       = var.enable_slack_notifications ? aws_lambda_function.slack_notification[0].arn : null
# }
