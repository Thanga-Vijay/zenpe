output "api_gateway_url" {
  description = "URL of the API Gateway"
  value       = module.api_gateway.api_url
}

output "domain_name" {
  description = "Domain name of the applications"
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

# output "redis_endpoint" {
#   description = "Endpoint of the Redis cluster"
#   value       = module.redis.endpoint
# }

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


