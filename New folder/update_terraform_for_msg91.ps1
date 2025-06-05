# PowerShell script to update Terraform files to replace Redis with MSG91
$baseDir = "C:\Users\ADMIN\Documents\APP\Continue\Backend"
$infraDir = Join-Path $baseDir "infrastructure"

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
    Write-Host "Updated file: $Path"
}

# Create MSG91 Terraform module
$msg91ModuleDir = Join-Path $infraDir "modules\msg91"
if (!(Test-Path $msg91ModuleDir)) {
    New-Item -ItemType Directory -Path $msg91ModuleDir -Force | Out-Null
}

# MSG91 module main.tf
$msg91MainTf = @'
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
'@

# MSG91 module variables.tf
$msg91VariablesTf = @'
variable "app_name" {
  description = "Name of the application"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "msg91_auth_key" {
  description = "MSG91 Authentication Key"
  type        = string
  sensitive   = true
}

variable "msg91_template_id" {
  description = "MSG91 Template ID for OTP"
  type        = string
}

variable "msg91_sender_id" {
  description = "MSG91 Sender ID"
  type        = string
  default     = "OTPSMS"
}

variable "msg91_dlt_te_id" {
  description = "MSG91 DLT Template Entity ID (for Indian regulations)"
  type        = string
  default     = ""
}

variable "msg91_route" {
  description = "MSG91 Route (4 for transactional, 1 for promotional)"
  type        = string
  default     = "4"
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
'@

# MSG91 module outputs.tf
$msg91OutputsTf = @'
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
'@

Set-FileContent -Path (Join-Path $msg91ModuleDir "main.tf") -Content $msg91MainTf
Set-FileContent -Path (Join-Path $msg91ModuleDir "variables.tf") -Content $msg91VariablesTf
Set-FileContent -Path (Join-Path $msg91ModuleDir "outputs.tf") -Content $msg91OutputsTf

Write-Host "Created MSG91 Terraform module"

# Add MSG91 variables to variables.tf
$variablesPath = Join-Path $infraDir "variables.tf"
if (Test-Path $variablesPath) {
    $variablesContent = Get-Content -Path $variablesPath -Raw
    
    # Add MSG91 variables if they don't exist
    $msg91Variables = @'

# MSG91 Variables
variable "msg91_auth_key" {
  description = "MSG91 Authentication Key"
  type        = string
  sensitive   = true
}

variable "msg91_template_id" {
  description = "MSG91 Template ID for OTP"
  type        = string
}

variable "msg91_sender_id" {
  description = "MSG91 Sender ID"
  type        = string
  default     = "OTPSMS"
}

variable "msg91_dlt_te_id" {
  description = "MSG91 DLT Template Entity ID (for Indian regulations)"
  type        = string
  default     = ""
}

variable "msg91_route" {
  description = "MSG91 Route (4 for transactional, 1 for promotional)"
  type        = string
  default     = "4"
}
'@

    if (-not ($variablesContent -match "msg91_auth_key")) {
        $variablesContent += $msg91Variables
        Set-FileContent -Path $variablesPath -Content $variablesContent
        Write-Host "Added MSG91 variables to variables.tf"
    } else {
        Write-Host "MSG91 variables already exist in variables.tf"
    }
}

# Update terraform.tfvars.example to include MSG91 settings
$tfvarsExamplePath = Join-Path $infraDir "terraform.tfvars.example"
if (Test-Path $tfvarsExamplePath) {
    $tfvarsContent = Get-Content -Path $tfvarsExamplePath -Raw
    
    # Add MSG91 settings if they don't exist
    $msg91Settings = @'

# MSG91 Settings
msg91_auth_key = "your-msg91-auth-key"
msg91_template_id = "your-msg91-template-id"
msg91_sender_id = "OTPSMS"
msg91_dlt_te_id = "your-dlt-te-id"
msg91_route = "4"
'@

    if (-not ($tfvarsContent -match "msg91_auth_key")) {
        $tfvarsContent += $msg91Settings
        Set-FileContent -Path $tfvarsExamplePath -Content $tfvarsContent
        Write-Host "Added MSG91 settings to terraform.tfvars.example"
    } else {
        Write-Host "MSG91 settings already exist in terraform.tfvars.example"
    }
}

# Update main.tf to replace Redis with MSG91
$mainTfPath = Join-Path $infraDir "main.tf"
if (Test-Path $mainTfPath) {
    $mainTfContent = Get-Content -Path $mainTfPath -Raw
    
    # Add MSG91 module reference
    $msg91ModuleBlock = @'

# MSG91 Integration for OTP
module "msg91" {
  source = "./modules/msg91"
  
  app_name        = var.app_name
  environment     = var.environment
  msg91_auth_key  = var.msg91_auth_key
  msg91_template_id = var.msg91_template_id
  msg91_sender_id = var.msg91_sender_id
  msg91_dlt_te_id = var.msg91_dlt_te_id
  alarm_actions   = [module.monitoring.alarm_topic_arn]
  ok_actions      = [module.monitoring.alarm_topic_arn]
}
'@

    # 1. Remove Redis module if it exists
    $redisModulePattern = "# Redis for OTP and caching\r?\nmodule\s+""redis""\s+\{[\s\S]*?\}"
    $updatedMainTf = $mainTfContent -replace $redisModulePattern, ""
    
    # 2. Add MSG91 module before ECS cluster module
    $ecsModulePattern = "# ECS Cluster\r?\nmodule\s+""ecs""\s+\{"
    $updatedMainTf = $updatedMainTf -replace $ecsModulePattern, "$msg91ModuleBlock`n`n# ECS Cluster`nmodule ""ecs"" {"
    
    # 3. Update OTP service module to use MSG91 instead of Redis
    $otpServicePattern = "# ECS Services - OTP Service\r?\nmodule\s+""otp_service""\s+\{[\s\S]*?environment_variables\s+=\s+\[[\s\S]*?\][\s\S]*?\}"
    $otpServiceBlock = @'
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
    { name = "AWS_REGION", value = var.aws_region }
  ]
  
  secrets = [
    { name = "MSG91_AUTH_KEY", valueFrom = "${module.msg91.secret_arn}:auth_key::" },
    { name = "MSG91_TEMPLATE_ID", valueFrom = "${module.msg91.secret_arn}:template_id::" },
    { name = "MSG91_SENDER_ID", valueFrom = "${module.msg91.secret_arn}:sender_id::" },
    { name = "MSG91_DLT_TE_ID", valueFrom = "${module.msg91.secret_arn}:dlt_te_id::" },
    { name = "SMTP_USERNAME", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:smtp.username::" },
    { name = "SMTP_PASSWORD", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:smtp.password::" }
  ]
}
'@

    $updatedMainTf = $updatedMainTf -replace $otpServicePattern, $otpServiceBlock
    
    # 4. Remove Redis dependency from User Service
    $userServicePattern = "environment_variables\s+=\s+\[\s*\{\s*name\s+=\s+""DATABASE_URL"",\s*value\s+=\s+""postgresql://.*?\s*\},\s*\{\s*name\s+=\s+""REDIS_HOST"",\s*value\s+=\s+module\.redis\.endpoint\s*\},\s*\{\s*name\s+=\s+""AWS_REGION"",\s*value\s+=\s+var\.aws_region\s*\}\s*\]"
    $userServiceReplacement = @'
environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/user_service" },
    { name = "AWS_REGION", value = var.aws_region }
  ]
'@

    $updatedMainTf = $updatedMainTf -replace $userServicePattern, $userServiceReplacement
    
    # 5. Update Secrets Manager to include MSG91
    $secretsManagerPattern = "secret_string\s+=\s+jsonencode\(\{[\s\S]*?\}\)"
    $secretsManagerBlock = @'
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
    msg91 = {
      auth_key    = var.msg91_auth_key
      template_id = var.msg91_template_id
      sender_id   = var.msg91_sender_id
      dlt_te_id   = var.msg91_dlt_te_id
    }
  })
'@

    $updatedMainTf = $updatedMainTf -replace $secretsManagerPattern, $secretsManagerBlock
    
    # Write the updated content back to main.tf
    Set-FileContent -Path $mainTfPath -Content $updatedMainTf
    Write-Host "Updated main.tf to replace Redis with MSG91"
}

Write-Host "Terraform files have been updated to replace Redis with MSG91 for OTP service"
Write-Host "Please review the changes to ensure everything is correct"