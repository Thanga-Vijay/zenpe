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
