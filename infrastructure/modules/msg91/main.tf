# This module integrates MSG91 credentials into your infrastructure
# It provides a standardized way to manage MSG91 credentials
# across different environments and services

# Store MSG91 credentials in AWS Secrets Manager
resource "aws_secretsmanager_secret" "msg91_credentials" {
  name = "${var.app_name}-msg91-credentials-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-msg91-credentials"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "msg91_credentials" {
  secret_id = aws_secretsmanager_secret.msg91_credentials.id
  secret_string = jsonencode({
    auth_key    = var.msg91_auth_key
    template_id = var.msg91_template_id
    sender_id   = var.msg91_sender_id
    dlt_te_id   = var.msg91_dlt_te_id
    route       = var.msg91_route
  })
}

# IAM policy to allow access to MSG91 credentials
resource "aws_iam_policy" "msg91_access" {
  name        = "${var.app_name}-msg91-access-${var.environment}"
  description = "Allow access to MSG91 credentials in Secrets Manager"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Effect   = "Allow"
        Resource = aws_secretsmanager_secret.msg91_credentials.arn
      }
    ]
  })
}

# CloudWatch alarm for MSG91 failures
resource "aws_cloudwatch_metric_alarm" "msg91_failures" {
  alarm_name          = "${var.app_name}-msg91-failures-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "${var.app_name}-msg91-failure-count"
  namespace           = "CustomMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Number of MSG91 API failures is too high"
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  insufficient_data_actions = []
  
  tags = {
    Name        = "${var.app_name}-msg91-failures"
    Environment = var.environment
  }
}
