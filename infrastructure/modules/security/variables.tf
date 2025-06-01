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

variable "admin_whitelisted_ips" {
  description = "List of IPs whitelisted for admin access"
  type        = list(string)
  default     = []
}

variable "kyc_service_security_group_id" {
  description = "Security group ID for the KYC service"
  type        = string
}