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

# MSG91 Variables
# variable "msg91_auth_key" {
#   description = "MSG91 Auth Key"
#   sensitive   = true
# }

# variable "msg91_template_id" {
#   description = "MSG91 Template ID"
#   sensitive   = true
# }
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


# KYC Service Variables
variable "kyc_admin_allowed_ips" {
  description = "List of IP addresses allowed to access KYC admin interface"
  type        = list(string)
  default     = []
}

variable "kyc_admin_session_timeout" {
  description = "Timeout in minutes for KYC admin sessions"
  type        = number
  default     = 30
}

variable "kyc_document_retention_days" {
  description = "Number of days to retain KYC documents before automatic deletion"
  type        = number
  default     = 90  # Adjust based on your compliance requirements
}

variable "kyc_admin_email_notifications" {
  description = "List of admin email addresses for KYC verification notifications"
  type        = list(string)
  default     = []
}

variable "kyc_watermark_text" {
  description = "Text to be used for watermarking KYC documents"
  type        = string
  default     = "Confidential - For KYC Verification Only"
}

variable "kyc_backup_retention_days" {
  description = "Number of days to retain KYC data backups"
  type        = number
  default     = 365  # Adjust based on your compliance requirements
}



