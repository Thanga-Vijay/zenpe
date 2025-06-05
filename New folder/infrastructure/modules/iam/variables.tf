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
