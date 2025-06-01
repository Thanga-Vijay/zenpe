# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.app_name}-${var.environment}"
  retention_in_days = var.log_retention_days
  
  tags = {
    Name        = "${var.app_name}-ecs-logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.app_name}-${var.environment}"
  retention_in_days = var.log_retention_days
  
  tags = {
    Name        = "${var.app_name}-api-gateway-logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "rds" {
  name              = "/aws/rds/${var.app_name}-${var.environment}"
  retention_in_days = var.log_retention_days
  
  tags = {
    Name        = "${var.app_name}-rds-logs"
    Environment = var.environment
  }
}

# CloudWatch Alarms for ECS services
resource "aws_cloudwatch_metric_alarm" "ecs_cpu_high" {
  for_each = var.ecs_services
  
  alarm_name          = "${each.key}-cpu-utilization-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "CPU utilization is too high"
  
  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = each.key
  }
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  tags = {
    Name        = "${each.key}-cpu-utilization-high"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_memory_high" {
  for_each = var.ecs_services
  
  alarm_name          = "${each.key}-memory-utilization-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Memory utilization is too high"
  
  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = each.key
  }
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  tags = {
    Name        = "${each.key}-memory-utilization-high"
    Environment = var.environment
  }
}

# CloudWatch Alarm for ALB 5XX errors
resource "aws_cloudwatch_metric_alarm" "alb_5xx_errors" {
  alarm_name          = "${var.app_name}-alb-5xx-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "ALB 5XX error count is too high"
  
  dimensions = {
    LoadBalancer = var.alb_name
  }
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  tags = {
    Name        = "${var.app_name}-alb-5xx-errors"
    Environment = var.environment
  }
}

# CloudWatch Alarm for 4XX errors
resource "aws_cloudwatch_metric_alarm" "alb_4xx_errors" {
  alarm_name          = "${var.app_name}-alb-4xx-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_4XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "ALB 4XX error count is too high"
  
  dimensions = {
    LoadBalancer = var.alb_name
  }
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  tags = {
    Name        = "${var.app_name}-alb-4xx-errors"
    Environment = var.environment
  }
}

# CloudWatch Alarm for target response time
resource "aws_cloudwatch_metric_alarm" "target_response_time" {
  alarm_name          = "${var.app_name}-target-response-time-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Target response time is too high"
  
  dimensions = {
    LoadBalancer = var.alb_name
  }
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  tags = {
    Name        = "${var.app_name}-target-response-time"
    Environment = var.environment
  }
}

# CloudWatch Alarm for RDS CPU
resource "aws_cloudwatch_metric_alarm" "rds_cpu_high" {
  alarm_name          = "${var.app_name}-rds-cpu-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU utilization is too high"
  
  dimensions = {
    DBClusterIdentifier = var.rds_cluster_id
  }
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  tags = {
    Name        = "${var.app_name}-rds-cpu-high"
    Environment = var.environment
  }
}

# CloudWatch Alarm for RDS free storage space
resource "aws_cloudwatch_metric_alarm" "rds_free_storage_low" {
  alarm_name          = "${var.app_name}-rds-free-storage-low-${var.environment}"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 10000000000  # 10GB in bytes
  alarm_description   = "RDS free storage space is too low"
  
  dimensions = {
    DBClusterIdentifier = var.rds_cluster_id
  }
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  tags = {
    Name        = "${var.app_name}-rds-free-storage-low"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "kyc_verification_delay" {
  alarm_name          = "${var.app_name}-kyc-verification-delay-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "VerificationDelay"
  namespace           = "KYCService"
  period              = "300"
  statistic           = "Average"
  threshold           = "3600"
  alarm_description   = "KYC verification taking longer than 1 hour"
  alarm_actions       = [var.sns_topic_arn]
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.app_name}-dashboard-${var.environment}"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# ${var.app_name} Dashboard - ${var.environment}"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_name]
          ]
          view    = "timeSeries"
          stacked = false
          title   = "ALB Request Count"
          region  = var.aws_region
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 1
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", var.alb_name],
            ["AWS/ApplicationELB", "HTTPCode_ELB_4XX_Count", "LoadBalancer", var.alb_name]
          ]
          view    = "timeSeries"
          stacked = false
          title   = "ALB Error Codes"
          region  = var.aws_region
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 24
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.alb_name]
          ]
          view    = "timeSeries"
          stacked = false
          title   = "Target Response Time"
          region  = var.aws_region
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 13
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBClusterIdentifier", var.rds_cluster_id]
          ]
          view    = "timeSeries"
          stacked = false
          title   = "RDS CPU Utilization"
          region  = var.aws_region
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 13
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/RDS", "DatabaseConnections", "DBClusterIdentifier", var.rds_cluster_id]
          ]
          view    = "timeSeries"
          stacked = false
          title   = "RDS Database Connections"
          region  = var.aws_region
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 19
        width  = 24
        height = 6
        properties = {
          metrics = []
          view    = "timeSeries"
          stacked = false
          title   = "ECS CPU Utilization by Service"
          region  = var.aws_region
          period  = 300
          yAxis = {
            left = {
              min = 0
              max = 100
            }
          }
        }
      }
    ]
  })
}

# SNS Topic for Alarms
resource "aws_sns_topic" "alarms" {
  name = "${var.app_name}-alarms-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-alarms"
    Environment = var.environment
  }
}

# Lambda function for sending alarm notifications to Slack (optional)
resource "aws_lambda_function" "slack_notification" {
  count = var.enable_slack_notifications ? 1 : 0
  
  function_name    = "${var.app_name}-slack-notification-${var.environment}"
  role             = aws_iam_role.lambda_execution_role[0].arn
  handler          = "index.handler"
  runtime          = "nodejs14.x"
  filename         = "${path.module}/lambda/slack-notification.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda/slack-notification.zip")
  
  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      SLACK_CHANNEL     = var.slack_channel
    }
  }
  
  tags = {
    Name        = "${var.app_name}-slack-notification"
    Environment = var.environment
  }
}

# IAM Role for Lambda function
resource "aws_iam_role" "lambda_execution_role" {
  count = var.enable_slack_notifications ? 1 : 0
  
  name = "${var.app_name}-lambda-execution-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name        = "${var.app_name}-lambda-execution-role"
    Environment = var.environment
  }
}

# IAM Policy for Lambda function
resource "aws_iam_policy" "lambda_execution_policy" {
  count = var.enable_slack_notifications ? 1 : 0
  
  name        = "${var.app_name}-lambda-execution-policy-${var.environment}"
  description = "Policy for ${var.app_name} Lambda function"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "lambda_execution_policy_attachment" {
  count = var.enable_slack_notifications ? 1 : 0
  
  role       = aws_iam_role.lambda_execution_role[0].name
  policy_arn = aws_iam_policy.lambda_execution_policy[0].arn
}

# SNS subscription for Lambda
resource "aws_sns_topic_subscription" "lambda_subscription" {
  count = var.enable_slack_notifications ? 1 : 0
  
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.slack_notification[0].arn
}

# SNS subscription for Email
resource "aws_sns_topic_subscription" "email_subscription" {
  count = length(var.alarm_email_addresses) > 0 ? length(var.alarm_email_addresses) : 0
  
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email_addresses[count.index]
}

# CloudWatch Log Metric Filter for Error logs
resource "aws_cloudwatch_log_metric_filter" "error_logs" {
  name           = "${var.app_name}-error-logs-${var.environment}"
  pattern        = "ERROR"
  log_group_name = aws_cloudwatch_log_group.ecs.name
  
  metric_transformation {
    name      = "${var.app_name}-error-count"
    namespace = "LogMetrics"
    value     = "1"
  }
}

# CloudWatch Alarm for Error logs
resource "aws_cloudwatch_metric_alarm" "error_logs_alarm" {
  alarm_name          = "${var.app_name}-error-logs-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "${var.app_name}-error-count"
  namespace           = "LogMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Number of error logs is too high"
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  tags = {
    Name        = "${var.app_name}-error-logs"
    Environment = var.environment
  }
}
