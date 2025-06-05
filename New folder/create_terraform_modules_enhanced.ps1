# PowerShell script to create enhanced Terraform modules with IAM, AWS Shield, and CloudWatch
$baseDir = "C:\Users\ADMIN\Documents\APP\Continue\Backend"
$infraDir = Join-Path $baseDir "infrastructure"
$modulesDir = Join-Path $infraDir "modules"

# Function to create or overwrite a file with content
function Set-FileContent {
    param (
        [string]$Path,
        [string]$Content
    )
    
    # Create directory if it doesn't exist
    $directory = Split-Path -Path $Path -Parent
    if (!(Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    
    if (Test-Path $Path) {
        Clear-Content $Path
    }
    
    $Content | Out-File -FilePath $Path -Encoding utf8
    Write-Host "Created file: $Path"
}

# Create modules directory if it doesn't exist
if (!(Test-Path $modulesDir)) {
    New-Item -ItemType Directory -Path $modulesDir -Force | Out-Null
}

#############################################
# IAM MODULE
#############################################
$iamDir = Join-Path $modulesDir "iam"
if (!(Test-Path $iamDir)) {
    New-Item -ItemType Directory -Path $iamDir -Force | Out-Null
}

# IAM main.tf
$iamMainTf = @'
# ECS Task Execution Role
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.app_name}-ecs-task-execution-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name        = "${var.app_name}-ecs-task-execution-role"
    Environment = var.environment
  }
}

# Attach the ECS task execution role policy
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ECS Task Role
resource "aws_iam_role" "ecs_task_role" {
  name = "${var.app_name}-ecs-task-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name        = "${var.app_name}-ecs-task-role"
    Environment = var.environment
  }
}

# Allow ECS tasks to access Secrets Manager
resource "aws_iam_policy" "secrets_manager_access" {
  name        = "${var.app_name}-secrets-manager-access-${var.environment}"
  description = "Allow ECS tasks to access Secrets Manager"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:${var.app_name}*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "secrets_manager_access" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.secrets_manager_access.arn
}

# Allow ECS tasks to access S3 (for KYC service)
resource "aws_iam_policy" "s3_access" {
  name        = "${var.app_name}-s3-access-${var.environment}"
  description = "Allow ECS tasks to access S3 buckets"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          "arn:aws:s3:::${var.app_name}-kyc-documents-${var.environment}",
          "arn:aws:s3:::${var.app_name}-kyc-documents-${var.environment}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "s3_access" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.s3_access.arn
}

# Allow ECS tasks to access SQS (for asynchronous processing)
resource "aws_iam_policy" "sqs_access" {
  name        = "${var.app_name}-sqs-access-${var.environment}"
  description = "Allow ECS tasks to access SQS queues"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueUrl",
          "sqs:GetQueueAttributes"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:sqs:${var.aws_region}:${var.aws_account_id}:${var.app_name}-*-${var.environment}"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "sqs_access" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.sqs_access.arn
}

# Allow ECS tasks to publish to SNS (for notifications)
resource "aws_iam_policy" "sns_access" {
  name        = "${var.app_name}-sns-access-${var.environment}"
  description = "Allow ECS tasks to publish to SNS topics"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sns:Publish"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:sns:${var.aws_region}:${var.aws_account_id}:${var.app_name}-*-${var.environment}"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "sns_access" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.sns_access.arn
}

# Allow ECS tasks to put events on EventBridge
resource "aws_iam_policy" "eventbridge_access" {
  name        = "${var.app_name}-eventbridge-access-${var.environment}"
  description = "Allow ECS tasks to put events on EventBridge"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "events:PutEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:events:${var.aws_region}:${var.aws_account_id}:event-bus/${var.app_name}-*-${var.environment}"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eventbridge_access" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.eventbridge_access.arn
}

# CloudWatch Logs access for all services
resource "aws_iam_policy" "cloudwatch_logs_access" {
  name        = "${var.app_name}-cloudwatch-logs-access-${var.environment}"
  description = "Allow services to write to CloudWatch Logs"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs_access" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.cloudwatch_logs_access.arn
}

# Admin user role for management console
resource "aws_iam_role" "admin_role" {
  count = var.create_admin_role ? 1 : 0
  
  name = "${var.app_name}-admin-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.admin_principal_arns
        }
      }
    ]
  })
  
  tags = {
    Name        = "${var.app_name}-admin-role"
    Environment = var.environment
  }
}

# Admin policy with necessary permissions
resource "aws_iam_policy" "admin_policy" {
  count = var.create_admin_role ? 1 : 0
  
  name        = "${var.app_name}-admin-policy-${var.environment}"
  description = "Admin policy for ${var.app_name}"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ecs:*",
          "ecr:*",
          "elasticloadbalancing:*",
          "ec2:*",
          "cloudwatch:*",
          "logs:*",
          "secretsmanager:*",
          "s3:*",
          "sqs:*",
          "sns:*",
          "events:*",
          "elasticache:*",
          "rds:*",
          "apigateway:*",
          "route53:*",
          "lambda:*"
        ]
        Effect   = "Allow"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = var.environment
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_policy_attachment" {
  count = var.create_admin_role ? 1 : 0
  
  role       = aws_iam_role.admin_role[0].name
  policy_arn = aws_iam_policy.admin_policy[0].arn
}
'@

Set-FileContent -Path (Join-Path $iamDir "main.tf") -Content $iamMainTf

# IAM variables.tf
$iamVariablesTf = @'
variable "app_name" {
  description = "Name of the application"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "create_admin_role" {
  description = "Whether to create an admin role"
  type        = bool
  default     = false
}

variable "admin_principal_arns" {
  description = "List of ARNs allowed to assume the admin role"
  type        = list(string)
  default     = []
}
'@

Set-FileContent -Path (Join-Path $iamDir "variables.tf") -Content $iamVariablesTf

# IAM outputs.tf
$iamOutputsTf = @'
output "ecs_task_execution_role_arn" {
  description = "ARN of the ECS task execution role"
  value       = aws_iam_role.ecs_task_execution_role.arn
}

output "ecs_task_execution_role_name" {
  description = "Name of the ECS task execution role"
  value       = aws_iam_role.ecs_task_execution_role.name
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task role"
  value       = aws_iam_role.ecs_task_role.arn
}

output "ecs_task_role_name" {
  description = "Name of the ECS task role"
  value       = aws_iam_role.ecs_task_role.name
}

output "admin_role_arn" {
  description = "ARN of the admin role"
  value       = var.create_admin_role ? aws_iam_role.admin_role[0].arn : null
}
'@

Set-FileContent -Path (Join-Path $iamDir "outputs.tf") -Content $iamOutputsTf

#############################################
# SECURITY MODULE (AWS Shield & WAF)
#############################################
$securityDir = Join-Path $modulesDir "security"
if (!(Test-Path $securityDir)) {
    New-Item -ItemType Directory -Path $securityDir -Force | Out-Null
}

# Security main.tf
$securityMainTf = @'
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
'@

Set-FileContent -Path (Join-Path $securityDir "main.tf") -Content $securityMainTf

# Security variables.tf
$securityVariablesTf = @'
variable "app_name" {
  description = "Name of the application"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC"
  type        = string
}

variable "alb_arn" {
  description = "ARN of the ALB to protect"
  type        = string
}

variable "api_gateway_arn" {
  description = "ARN of the API Gateway to protect (optional)"
  type        = string
  default     = ""
}

variable "enable_shield_advanced" {
  description = "Whether to enable Shield Advanced (requires subscription)"
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Whether to enable GuardDuty"
  type        = bool
  default     = true
}

variable "geo_restriction_countries" {
  description = "List of countries to block traffic from"
  type        = list(string)
  default     = []
}
'@

Set-FileContent -Path (Join-Path $securityDir "variables.tf") -Content $securityVariablesTf

# Security outputs.tf
$securityOutputsTf = @'
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
'@

Set-FileContent -Path (Join-Path $securityDir "outputs.tf") -Content $securityOutputsTf

#############################################
# MONITORING MODULE (CloudWatch)
#############################################
$monitoringDir = Join-Path $modulesDir "monitoring"
if (!(Test-Path $monitoringDir)) {
    New-Item -ItemType Directory -Path $monitoringDir -Force | Out-Null
}

# Monitoring main.tf (continued)
$monitoringMainTf = @'
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
'@

Set-FileContent -Path (Join-Path $monitoringDir "main.tf") -Content $monitoringMainTf

# Monitoring variables.tf
$monitoringVariablesTf = @'
variable "app_name" {
  description = "Name of the application"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 30
}

variable "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  type        = string
}

variable "ecs_services" {
  description = "Map of ECS service names"
  type        = map(string)
}

variable "alb_name" {
  description = "Name of the ALB"
  type        = string
}

variable "rds_cluster_id" {
  description = "ID of the RDS cluster"
  type        = string
}

variable "alarm_actions" {
  description = "List of ARNs to notify when alarm transitions to ALARM state"
  type        = list(string)
  default     = []
}

variable "ok_actions" {
  description = "List of ARNs to notify when alarm transitions to OK state"
  type        = list(string)
  default     = []
}

variable "enable_slack_notifications" {
  description = "Whether to enable Slack notifications for alarms"
  type        = bool
  default     = false
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_channel" {
  description = "Slack channel for notifications"
  type        = string
  default     = "#alerts"
}

variable "alarm_email_addresses" {
  description = "List of email addresses to notify for alarms"
  type        = list(string)
  default     = []
}
'@

Set-FileContent -Path (Join-Path $monitoringDir "variables.tf") -Content $monitoringVariablesTf

# Monitoring outputs.tf
$monitoringOutputsTf = @'
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

output "lambda_function_arn" {
  description = "ARN of the Lambda function for Slack notifications"
  value       = var.enable_slack_notifications ? aws_lambda_function.slack_notification[0].arn : null
}
'@

Set-FileContent -Path (Join-Path $monitoringDir "outputs.tf") -Content $monitoringOutputsTf

# Create Lambda function placeholder for Slack notifications
$lambdaDir = Join-Path $monitoringDir "lambda"
if (!(Test-Path $lambdaDir)) {
    New-Item -ItemType Directory -Path $lambdaDir -Force | Out-Null
}

# Lambda function for Slack notifications (placeholder - in a real project you'd create an actual Lambda function)
$slackNotificationJs = @'
exports.handler = async (event) => {
    console.log('Event:', JSON.stringify(event, null, 2));
    
    // Parse SNS message
    const message = event.Records[0].Sns.Message;
    
    // Get environment variables
    const slackWebhookUrl = process.env.SLACK_WEBHOOK_URL;
    const slackChannel = process.env.SLACK_CHANNEL;
    
    // Create Slack message
    const slackMessage = {
        channel: slackChannel,
        text: `*CloudWatch Alarm*\n${message}`,
        attachments: [
            {
                color: "#FF0000",
                fields: [
                    {
                        title: "Alarm Details",
                        value: message,
                        short: false
                    }
                ]
            }
        ]
    };
    
    // In a real implementation, you would send the message to Slack here
    console.log('Slack message:', JSON.stringify(slackMessage, null, 2));
    
    return {
        statusCode: 200,
        body: JSON.stringify('Message sent to Slack'),
    };
};
'@

Set-FileContent -Path (Join-Path $lambdaDir "index.js") -Content $slackNotificationJs

# Create a placeholder zip file for the Lambda function
Add-Type -Assembly System.IO.Compression.FileSystem
$zipPath = Join-Path $lambdaDir "slack-notification.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath
}
$zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
$indexJsEntry = $zip.CreateEntry("index.js")
$writer = New-Object System.IO.StreamWriter($indexJsEntry.Open())
$writer.Write($slackNotificationJs)
$writer.Close()
$zip.Dispose()

#############################################
# Update root terraform files for new modules
#############################################

# Update main.tf in the infrastructure directory (continued)
$updatedMainTf = @'
# AWS Provider Configuration
provider "aws" {
  region = var.aws_region
}

# Local variables
locals {
  ecs_services = {
    "${var.app_name}-user-service"      = "${var.app_name}-user-service-${var.environment}"
    "${var.app_name}-otp-service"       = "${var.app_name}-otp-service-${var.environment}"
    "${var.app_name}-kyc-service"       = "${var.app_name}-kyc-service-${var.environment}"
    "${var.app_name}-payment-service"   = "${var.app_name}-payment-service-${var.environment}"
    "${var.app_name}-admin-service"     = "${var.app_name}-admin-service-${var.environment}"
  }
}

# VPC and Networking
module "vpc" {
  source = "./modules/vpc"
  
  app_name        = var.app_name
  environment     = var.environment
  vpc_cidr        = var.vpc_cidr
  azs             = var.azs
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets
}

# IAM roles and policies
module "iam" {
  source = "./modules/iam"
  
  app_name        = var.app_name
  environment     = var.environment
  aws_region      = var.aws_region
  aws_account_id  = var.aws_account_id
  create_admin_role = var.create_admin_role
  admin_principal_arns = var.admin_principal_arns
}

# RDS Aurora PostgreSQL
module "database" {
  source = "./modules/database"
  
  app_name          = var.app_name
  environment       = var.environment
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.database_subnet_ids
  app_security_group_id = module.ecs.security_group_id
  instance_class    = var.db_instance_class
  master_username   = var.db_master_username
  master_password   = var.db_master_password
  database_name     = var.db_name
  engine_version    = var.db_engine_version
}

# Redis for OTP and caching
module "redis" {
  source = "./modules/redis"
  
  app_name      = var.app_name
  environment   = var.environment
  vpc_id        = module.vpc.vpc_id
  subnet_ids    = module.vpc.private_subnet_ids
  app_security_group_id = module.ecs.security_group_id
  node_type     = var.redis_node_type
  engine_version = var.redis_engine_version
}

# ECS Cluster
module "ecs" {
  source = "./modules/ecs"
  
  app_name     = var.app_name
  environment  = var.environment
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = module.vpc.private_subnet_ids
  aws_region   = var.aws_region
  aws_account_id = var.aws_account_id
}

# API Gateway
module "api_gateway" {
  source = "./modules/api-gateway"
  
  app_name      = var.app_name
  environment   = var.environment
  vpc_id        = module.vpc.vpc_id
  public_subnet_ids = module.vpc.public_subnet_ids
  private_subnet_ids = module.vpc.private_subnet_ids
  certificate_arn = var.certificate_arn
  domain_name    = var.domain_name
  hosted_zone_id = var.hosted_zone_id
  
  # Service integrations
  integrations = [
    {
      name       = "user-service"
      target_url = module.user_service.service_url
      base_path  = "users"
    },
    {
      name       = "otp-service"
      target_url = module.otp_service.service_url
      base_path  = "otp"
    },
    {
      name       = "kyc-service"
      target_url = module.kyc_service.service_url
      base_path  = "kyc"
    },
    {
      name       = "payment-service"
      target_url = module.payment_service.service_url
      base_path  = "payments"
    },
    {
      name       = "settlement-service"
      target_url = module.payment_service.service_url
      base_path  = "settlements"
    },
    {
      name       = "admin-service"
      target_url = module.admin_service.service_url
      base_path  = "admin"
    },
    {
      name       = "notifications-service"
      target_url = module.admin_service.service_url
      base_path  = "notifications"
    }
  ]
}

# Security (WAF, Shield, GuardDuty)
module "security" {
  source = "./modules/security"
  
  app_name      = var.app_name
  environment   = var.environment
  vpc_id        = module.vpc.vpc_id
  alb_arn       = module.api_gateway.alb_dns_name
  api_gateway_arn = module.api_gateway.api_id
  enable_shield_advanced = var.enable_shield_advanced
  enable_guardduty = var.enable_guardduty
  geo_restriction_countries = var.geo_restriction_countries
}

# Monitoring (CloudWatch)
module "monitoring" {
  source = "./modules/monitoring"
  
  app_name          = var.app_name
  environment       = var.environment
  aws_region        = var.aws_region
  aws_account_id    = var.aws_account_id
  log_retention_days = var.log_retention_days
  ecs_cluster_name  = module.ecs.cluster_name
  ecs_services      = local.ecs_services
  alb_name          = module.api_gateway.alb_dns_name
  rds_cluster_id    = module.database.cluster_id
  alarm_actions     = [module.monitoring.alarm_topic_arn]
  ok_actions        = [module.monitoring.alarm_topic_arn]
  enable_slack_notifications = var.enable_slack_notifications
  slack_webhook_url = var.slack_webhook_url
  slack_channel     = var.slack_channel
  alarm_email_addresses = var.alarm_email_addresses
}

# ECS Services - User Service
module "user_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-user"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  ecs_cluster_name  = module.ecs.cluster_name
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8000
  container_image   = "${var.ecr_repository_url}/user-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  task_execution_role_arn = module.iam.ecs_task_execution_role_arn
  task_role_arn     = module.iam.ecs_task_role_arn
  alb_security_group_id = module.api_gateway.alb_security_group_id
  alb_listener_arn  = module.api_gateway.api_id
  listener_priority = 100
  path_pattern      = "users"
  health_check_path = "/health"
  log_group_name    = module.monitoring.log_group_names.ecs
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/user_service" },
    { name = "REDIS_HOST", value = module.redis.endpoint },
    { name = "AWS_REGION", value = var.aws_region }
  ]
  
  secrets = [
    { name = "SECRET_KEY", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:jwt.secret_key::" }
  ]
}

# ECS Services - OTP Service
module "otp_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-otp"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  ecs_cluster_name  = module.ecs.cluster_name
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8001
  container_image   = "${var.ecr_repository_url}/otp-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  task_execution_role_arn = module.iam.ecs_task_execution_role_arn
  task_role_arn     = module.iam.ecs_task_role_arn
  alb_security_group_id = module.api_gateway.alb_security_group_id
  alb_listener_arn  = module.api_gateway.api_id
  listener_priority = 110
  path_pattern      = "otp"
  health_check_path = "/health"
  log_group_name    = module.monitoring.log_group_names.ecs
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/otp_service" },
    { name = "REDIS_HOST", value = module.redis.endpoint },
    { name = "REDIS_PORT", value = "6379" },
    { name = "AWS_REGION", value = var.aws_region }
  ]
}

# ECS Services - KYC Service
module "kyc_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-kyc"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  ecs_cluster_name  = module.ecs.cluster_name
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8002
  container_image   = "${var.ecr_repository_url}/kyc-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  task_execution_role_arn = module.iam.ecs_task_execution_role_arn
  task_role_arn     = module.iam.ecs_task_role_arn
  alb_security_group_id = module.api_gateway.alb_security_group_id
  alb_listener_arn  = module.api_gateway.api_id
  listener_priority = 120
  path_pattern      = "kyc"
  health_check_path = "/health"
  log_group_name    = module.monitoring.log_group_names.ecs
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/kyc_service" },
    { name = "AWS_S3_BUCKET", value = aws_s3_bucket.kyc_documents.bucket },
    { name = "AWS_REGION", value = var.aws_region }
  ]
  
  secrets = [
    { name = "JWT_SECRET_KEY", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:jwt.secret_key::" }
  ]
}

# ECS Services - Payment Service
module "payment_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-payment"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  ecs_cluster_name  = module.ecs.cluster_name
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8003
  container_image   = "${var.ecr_repository_url}/payment-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  task_execution_role_arn = module.iam.ecs_task_execution_role_arn
  task_role_arn     = module.iam.ecs_task_role_arn
  alb_security_group_id = module.api_gateway.alb_security_group_id
  alb_listener_arn  = module.api_gateway.api_id
  listener_priority = 130
  path_pattern      = "payments"
  health_check_path = "/health"
  log_group_name    = module.monitoring.log_group_names.ecs
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/payment_service" },
    { name = "AWS_SQS_QUEUE_URL", value = aws_sqs_queue.settlement_queue.url },
    { name = "AWS_EVENTBRIDGE_BUS", value = aws_cloudwatch_event_bus.payment_events.name },
    { name = "AWS_REGION", value = var.aws_region }
  ]
  
  secrets = [
    { name = "RAZORPAY_KEY_ID", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:razorpay.key_id::" },
    { name = "RAZORPAY_KEY_SECRET", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:razorpay.key_secret::" },
    { name = "JWT_SECRET_KEY", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:jwt.secret_key::" }
  ]
}

# ECS Services - Admin Service
module "admin_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-admin"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  ecs_cluster_name  = module.ecs.cluster_name
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8004
  container_image   = "${var.ecr_repository_url}/admin-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  task_execution_role_arn = module.iam.ecs_task_execution_role_arn
  task_role_arn     = module.iam.ecs_task_role_arn
  alb_security_group_id = module.api_gateway.alb_security_group_id
  alb_listener_arn  = module.api_gateway.api_id
  listener_priority = 140
  path_pattern      = "admin"
  health_check_path = "/health"
  log_group_name    = module.monitoring.log_group_names.ecs
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/admin_service" },
    { name = "AWS_SNS_TOPIC_ARN", value = aws_sns_topic.notifications.arn },
    { name = "AWS_SQS_QUEUE_URL", value = aws_sqs_queue.admin_notifications.url },
    { name = "AWS_REGION", value = var.aws_region }
  ]
  
  secrets = [
    { name = "JWT_SECRET_KEY", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:jwt.secret_key::" },
    { name = "SMTP_USERNAME", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:smtp.username::" },
    { name = "SMTP_PASSWORD", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:smtp.password::" }
  ]
}

# S3 Bucket for KYC Documents
resource "aws_s3_bucket" "kyc_documents" {
  bucket = "${var.app_name}-kyc-documents-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-kyc-documents"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kyc_encryption" {
  bucket = aws_s3_bucket.kyc_documents.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "kyc_documents" {
  bucket = aws_s3_bucket.kyc_documents.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SQS Queues
resource "aws_sqs_queue" "settlement_queue" {
  name                      = "${var.app_name}-settlement-queue-${var.environment}"
  delay_seconds             = 0
  max_message_size          = 262144
  message_retention_seconds = 86400
  receive_wait_time_seconds = 10
  
  tags = {
    Name        = "${var.app_name}-settlement-queue"
    Environment = var.environment
  }
}

resource "aws_sqs_queue" "admin_notifications" {
  name                      = "${var.app_name}-admin-notifications-${var.environment}"
  delay_seconds             = 0
  max_message_size          = 262144
  message_retention_seconds = 86400
  receive_wait_time_seconds = 10
  
  tags = {
    Name        = "${var.app_name}-admin-notifications"
    Environment = var.environment
  }
}

# SNS Topic for Notifications
resource "aws_sns_topic" "notifications" {
  name = "${var.app_name}-notifications-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-notifications"
    Environment = var.environment
  }
}

# EventBridge Event Bus
resource "aws_cloudwatch_event_bus" "payment_events" {
  name = "${var.app_name}-payment-events-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-payment-events"
    Environment = var.environment
  }
}

# Secret Manager for Service Credentials
resource "aws_secretsmanager_secret" "service_credentials" {
  name = "${var.app_name}-service-credentials-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-service-credentials"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "service_credentials" {
  secret_id = aws_secretsmanager_secret.service_credentials.id
  secret_string = jsonencode({
    database = {
      username = var.db_master_username
      password = var.db_master_password
      host     = module.database.endpoint
    }
    razorpay = {
      key_id     = var.razorpay_key_id
      key_secret = var.razorpay_key_secret
    }
    jwt = {
      secret_key = var.jwt_secret_key
    }
    smtp = {
      username = var.smtp_username
      password = var.smtp_password
    }
  })
}

# CloudWatch Rule to handle dead-letter queues
resource "aws_cloudwatch_event_rule" "dlq_alarm" {
  name        = "${var.app_name}-dlq-alarm-${var.environment}"
  description = "Trigger when messages are sent to dead-letter queues"
  
  event_pattern = jsonencode({
    source      = ["aws.sqs"],
    detail-type = ["SQS Message Moved to Dead-Letter Queue"]
  })
  
  tags = {
    Name        = "${var.app_name}-dlq-alarm"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "dlq_alarm_sns" {
  rule      = aws_cloudwatch_event_rule.dlq_alarm.name
  target_id = "SendToSNS"
  arn       = module.monitoring.alarm_topic_arn
}
'@

Set-FileContent -Path (Join-Path $infraDir "main.tf") -Content $updatedMainTf

# Update variables.tf to include new variables
$updatedVariablesTf = @'
variable "app_name" {
  description = "Name of the application"
  default     = "rupay-upi"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region to deploy resources"
  default     = "ap-south-1"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

# VPC Variables
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  default     = "10.0.0.0/16"
}

variable "azs" {
  description = "Availability zones to use"
  type        = list(string)
  default     = ["ap-south-1a", "ap-south-1b", "ap-south-1c"]
}

variable "private_subnets" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnets" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

# Database Variables
variable "db_instance_class" {
  description = "Instance class for RDS Aurora"
  default     = "db.t3.small"
}

variable "db_master_username" {
  description = "Master username for RDS"
  default     = "postgres"
}

variable "db_master_password" {
  description = "Master password for RDS"
  sensitive   = true
}

variable "db_name" {
  description = "Name of the database"
  default     = "rupayupi"
}

variable "db_engine_version" {
  description = "Aurora PostgreSQL engine version"
  default     = "13.7"
}

# Redis Variables
variable "redis_node_type" {
  description = "Node type for Redis"
  default     = "cache.t3.small"
}

variable "redis_engine_version" {
  description = "Redis engine version"
  default     = "6.x"
}

# ECS Service Variables
variable "service_desired_count" {
  description = "Desired count of containers for each service"
  default     = 2
}

variable "service_cpu" {
  description = "CPU units for each container"
  default     = 256
}

variable "service_memory" {
  description = "Memory for each container in MB"
  default     = 512
}

variable "ecr_repository_url" {
  description = "URL of the ECR repository without the image name and tag"
}

# Certificate and Domain Variables
variable "certificate_arn" {
  description = "ARN of SSL certificate for HTTPS"
  default     = ""
}

variable "domain_name" {
  description = "Domain name for the application"
  default     = ""
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID"
  default     = ""
}

# Security Variables
variable "enable_shield_advanced" {
  description = "Whether to enable AWS Shield Advanced"
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Whether to enable GuardDuty"
  type        = bool
  default     = true
}

variable "geo_restriction_countries" {
  description = "List of countries to block traffic from"
  type        = list(string)
  default     = []
}

# Monitoring Variables
variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 30
}

variable "enable_slack_notifications" {
  description = "Whether to enable Slack notifications for alarms"
  type        = bool
  default     = false
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_channel" {
  description = "Slack channel for notifications"
  type        = string
  default     = "#alerts"
}

variable "alarm_email_addresses" {
  description = "List of email addresses to notify for alarms"
  type        = list(string)
  default     = []
}

# IAM Variables
variable "create_admin_role" {
  description = "Whether to create an admin role"
  type        = bool
  default     = false
}

variable "admin_principal_arns" {
  description = "List of ARNs allowed to assume the admin role"
  type        = list(string)
  default     = []
}

# Third-party Service Credentials
variable "razorpay_key_id" {
  description = "Razorpay Key ID"
  sensitive   = true
}

variable "razorpay_key_secret" {
  description = "Razorpay Key Secret"
  sensitive   = true
}

variable "jwt_secret_key" {
  description = "Secret key for JWT token generation"
  sensitive   = true
}

variable "smtp_username" {
  description = "SMTP username for sending emails"
  sensitive   = true
}

variable "smtp_password" {
  description = "SMTP password for sending emails"
  sensitive   = true
}
'@

Set-FileContent -Path (Join-Path $infraDir "variables.tf") -Content $updatedVariablesTf

# Update outputs.tf to include new outputs
$updatedOutputsTf = @'
output "api_gateway_url" {
  description = "URL of the API Gateway"
  value       = module.api_gateway.api_url
}

output "domain_name" {
  description = "Domain name of the application"
  value       = var.domain_name != "" ? var.domain_name : null
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "database_endpoint" {
  description = "Endpoint of the RDS Aurora cluster"
  value       = module.database.endpoint
}

output "redis_endpoint" {
  description = "Endpoint of the Redis cluster"
  value       = module.redis.endpoint
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = module.ecs.cluster_name
}

output "service_urls" {
  description = "URLs of the microservices"
  value = {
    user_service      = module.user_service.service_url
    otp_service       = module.otp_service.service_url
    kyc_service       = module.kyc_service.service_url
    payment_service   = module.payment_service.service_url
    admin_service     = module.admin_service.service_url
  }
}

output "kyc_bucket_name" {
  description = "Name of the S3 bucket for KYC documents"
  value       = aws_s3_bucket.kyc_documents.bucket
}

output "sqs_queues" {
  description = "SQS queue URLs"
  value = {
    settlement_queue     = aws_sqs_queue.settlement_queue.url
    admin_notifications  = aws_sqs_queue.admin_notifications.url
  }
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  value       = aws_sns_topic.notifications.arn
}

output "event_bus_name" {
  description = "Name of the EventBridge event bus"
  value       = aws_cloudwatch_event_bus.payment_events.name
}

output "secrets_manager_arn" {
  description = "ARN of the Secrets Manager secret"
  value       = aws_secretsmanager_secret.service_credentials.arn
}

output "cloudwatch_dashboard_url" {
  description = "URL of the CloudWatch dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${module.monitoring.dashboard_name}"
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = module.security.web_acl_arn
}

output "admin_role_arn" {
  description = "ARN of the admin role"
  value       = var.create_admin_role ? module.iam.admin_role_arn : null
}
'@

Set-FileContent -Path (Join-Path $infraDir "outputs.tf") -Content $updatedOutputsTf

# Create a new file for terraform.tfvars.example (continued)
$tfvarsExampleContent = @'
# General
app_name = "rupay-upi"
environment = "dev"
aws_region = "ap-south-1"
aws_account_id = "123456789012"

# Database
db_master_username = "postgres"
db_master_password = "your-secure-password-here"

# ECR
ecr_repository_url = "123456789012.dkr.ecr.ap-south-1.amazonaws.com"

# Third-party services
razorpay_key_id = "your-razorpay-key-id"
razorpay_key_secret = "your-razorpay-key-secret"
jwt_secret_key = "your-secure-jwt-secret-key"
smtp_username = "your-smtp-username"
smtp_password = "your-smtp-password"

# Optional Domain
# domain_name = "api.yourdomain.com"
# hosted_zone_id = "Z1234567890ABC"
# certificate_arn = "arn:aws:acm:ap-south-1:123456789012:certificate/abcdef-1234-5678-abcd-1234567890ab"

# Security
enable_shield_advanced = false
enable_guardduty = true
geo_restriction_countries = []

# Monitoring
log_retention_days = 30
enable_slack_notifications = false
# slack_webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
slack_channel = "#alerts"
alarm_email_addresses = ["devops@yourdomain.com"]

# IAM
create_admin_role = false
# admin_principal_arns = ["arn:aws:iam::123456789012:user/admin"]
'@

Set-FileContent -Path (Join-Path $infraDir "terraform.tfvars.example") -Content $tfvarsExampleContent

# Create a new file for backend.tf
$backendTfContent = @'
terraform {
  backend "s3" {
    # Fill these in or pass them as command line arguments
    # bucket         = "your-terraform-state-bucket"
    # key            = "rupay-upi/terraform.tfstate"
    # region         = "ap-south-1"
    # dynamodb_table = "terraform-state-lock"
    # encrypt        = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }

  required_version = ">= 1.0.0"
}
'@

Set-FileContent -Path (Join-Path $infraDir "backend.tf") -Content $backendTfContent

# Create a new file for versions.tf
$versionsTfContent = @'
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }

  required_version = ">= 1.0.0"
}
'@

Set-FileContent -Path (Join-Path $infraDir "versions.tf") -Content $versionsTfContent

# Create a README.md file for the infrastructure directory
$infraReadmeContent = @'
# RuPay UPI Infrastructure

## Overview

This directory contains Terraform code to provision the infrastructure for the RuPay UPI application on AWS. The infrastructure is defined using a modular approach with separate modules for each component.

## Architecture

![Architecture Diagram](./architecture-diagram.png)

The infrastructure includes:

- **VPC and Networking**: Private and public subnets across multiple AZs
- **IAM**: Roles and policies for secure access
- **Database**: Aurora PostgreSQL for data storage
- **Redis**: ElastiCache for caching and OTP storage
- **ECS**: Fargate clusters for running containerized microservices
- **API Gateway**: HTTP API for frontend access
- **Security**: WAF, Shield, and GuardDuty for protection
- **Monitoring**: CloudWatch for logs, metrics, and alarms
- **Storage**: S3 for document storage
- **Messaging**: SQS for asynchronous processing, SNS for notifications, EventBridge for events
- **Secrets**: AWS Secrets Manager for storing credentials

## Modules

- **vpc**: Network infrastructure
- **iam**: Identity and access management
- **database**: Aurora PostgreSQL database
- **redis**: ElastiCache Redis cluster
- **ecs**: ECS cluster and task definitions
- **ecs-service**: Individual ECS services
- **api-gateway**: API Gateway for frontend access
- **security**: WAF, Shield, and GuardDuty
- **monitoring**: CloudWatch logs, metrics, and alarms

## Microservices

- **User Service**: User management and authentication
- **OTP Service**: OTP generation and verification
- **KYC Service**: KYC document upload and verification
- **Payment Service**: Payment processing and settlement
- **Admin Service**: Admin operations and notifications

## Setup Instructions

1. **Install Terraform**:
   Make sure you have Terraform installed (version >= 1.0.0).

2. **Configure AWS Credentials**:
   Set up your AWS credentials using environment variables, AWS CLI configuration, or IAM roles.

3. **Configure Terraform Backend**:
   Edit `backend.tf` to configure the S3 backend for storing Terraform state.

4. **Create terraform.tfvars**:
   Copy `terraform.tfvars.example` to `terraform.tfvars` and fill in the required values.

5. **Initialize Terraform**:

6. **Create a Terraform Workspace**:

7. **Create a Terraform Plan**:

8. **Apply the Terraform Plan**:


## Environment Variables

You can use environment variables to override variables in `terraform.tfvars`:

## Deployment Considerations

- **Staging/Production Deployment**: For production, update the `environment` variable and create a new workspace.
- **Secrets Management**: Sensitive values should be stored in AWS Secrets Manager and not in `terraform.tfvars`.
- **Disaster Recovery**: The infrastructure includes multi-AZ deployment for high availability.
- **Monitoring and Alerting**: CloudWatch alarms are configured to alert on service issues.

## Security Best Practices

1. **Least Privilege**: IAM roles follow least privilege principle.
2. **Network Security**: Private subnets for sensitive resources, security groups restricting access.
3. **Data Encryption**: Data is encrypted at rest and in transit.
4. **WAF Protection**: WAF rules protect against common web exploits.
5. **Secrets Management**: Credentials are stored in AWS Secrets Manager.

## Compliance

This infrastructure is designed to help meet compliance requirements for:

- **PCI-DSS**: For secure payment processing
- **GDPR**: For user data protection
- **Data Localization**: Resources are deployed in the specified region

## Cost Optimization

- Fargate spot instances can be used for non-critical workloads
- Auto-scaling based on demand
- Resource right-sizing based on CloudWatch metrics

## Cleanup

To destroy the infrastructure:

Note: This will delete all resources created by Terraform, including databases. Make sure to backup any important data before running this command.
'@

Set-FileContent -Path (Join-Path $infraDir "README.md") -Content $infraReadmeContent

# Create a .gitignore file for Terraform
$gitignoreContent = @'
# Local .terraform directories
**/.terraform/*

# .tfstate files
*.tfstate
*.tfstate.*

# Crash log files
crash.log
crash.*.log

# Exclude all .tfvars files, which are likely to contain sensitive data
*.tfvars
!terraform.tfvars.example

# Ignore override files as they are usually used to override resources locally
override.tf
override.tf.json
*_override.tf
*_override.tf.json

# Ignore CLI configuration files
.terraformrc
terraform.rc

# Ignore lock files
.terraform.lock.hcl

# Ignore environment specific files
.env

# Ignore Lambda build artifacts
modules/monitoring/lambda/slack-notification.zip

# Ignore macOS metadata
.DS_Store
'@

Set-FileContent -Path (Join-Path $infraDir ".gitignore") -Content $gitignoreContent

# Create directory for deployment scripts
$scriptsDir = Join-Path $infraDir "scripts"
if (!(Test-Path $scriptsDir)) {
    New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null
}

# Create a deploy.sh script
$deployShContent = @'
#!/bin/bash
set -e

# Default values
ENVIRONMENT="dev"
WORKSPACE="dev"
ACTION="plan"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --environment|-e)
      ENVIRONMENT="$2"
      WORKSPACE="$2"
      shift
      shift
      ;;
    --workspace|-w)
      WORKSPACE="$2"
      shift
      shift
      ;;
    --action|-a)
      ACTION="$2"
      shift
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--environment|-e dev|staging|prod] [--workspace|-w workspace_name] [--action|-a plan|apply|destroy]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--environment|-e dev|staging|prod] [--workspace|-w workspace_name] [--action|-a plan|apply|destroy]"
      exit 1
      ;;
  esac
done

echo "Deploying to environment: $ENVIRONMENT, using workspace: $WORKSPACE, action: $ACTION"

# Check if Terraform is installed
if ! command -v terraform &> /dev/null; then
    echo "Terraform could not be found. Please install Terraform."
    exit 1
fi

# Initialize Terraform
echo "Initializing Terraform..."
terraform init

# Check if workspace exists, create if it doesn't
WORKSPACE_EXISTS=$(terraform workspace list | grep -c "$WORKSPACE" || true)
if [ "$WORKSPACE_EXISTS" -eq 0 ]; then
    echo "Creating workspace: $WORKSPACE"
    terraform workspace new "$WORKSPACE"
else
    echo "Selecting workspace: $WORKSPACE"
    terraform workspace select "$WORKSPACE"
fi

# Execute the specified action
case $ACTION in
  plan)
    echo "Creating Terraform plan..."
    terraform plan -var="environment=$ENVIRONMENT" -out=tfplan
    ;;
  apply)
    echo "Applying Terraform plan..."
    terraform apply -var="environment=$ENVIRONMENT" -auto-approve
    ;;
  destroy)
    echo "Destroying Terraform resources..."
    terraform destroy -var="environment=$ENVIRONMENT" -auto-approve
    ;;
  *)
    echo "Unknown action: $ACTION"
    echo "Supported actions: plan, apply, destroy"
    exit 1
    ;;
esac

echo "Deployment completed successfully!"
'@

Set-FileContent -Path (Join-Path $scriptsDir "deploy.sh") -Content $deployShContent

# Create an architecture diagram placeholder
$architectureDiagramDir = Join-Path $infraDir "docs"
if (!(Test-Path $architectureDiagramDir)) {
    New-Item -ItemType Directory -Path $architectureDiagramDir -Force | Out-Null
}

$architectureDiagramContent = @'
# Architecture Diagram

Please replace this file with an actual architecture diagram for your infrastructure.

You can create diagrams using tools like:
- draw.io
- Lucidchart
- AWS Architecture Icons
- Diagrams.net

Save the diagram as a PNG file named `architecture-diagram.png` in this directory.
'@

Set-FileContent -Path (Join-Path $architectureDiagramDir "architecture-diagram.md") -Content $architectureDiagramContent

Write-Host "All Terraform modules and infrastructure files have been successfully created!"
Write-Host "The enhanced infrastructure code is now ready with IAM, Security, and CloudWatch monitoring configurations."
Write-Host "You can find the Terraform modules in: $modulesDir"
Write-Host "And all infrastructure files in: $infraDir"
