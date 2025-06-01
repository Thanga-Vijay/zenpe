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

variable "sns_topic_arn" {
  description = "The ARN of the SNS topic for alarm actions"
  type        = string
}