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
  admin_whitelisted_ips         = var.kyc_admin_allowed_ips
  kyc_service_security_group_id = module.kyc_service.security_group_id


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

resource "aws_s3_bucket_versioning" "kyc_documents" {
  bucket = aws_s3_bucket.kyc_documents.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "kyc_documents" {
  bucket = aws_s3_bucket.kyc_documents.id

  rule {
    id     = "glacier-transition"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.kyc_document_retention_days
      storage_class = "GLACIER"
    }
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
    msg91 = {
      auth_key    = var.msg91_auth_key
      template_id = var.msg91_template_id
      sender_id   = var.msg91_sender_id
      dlt_te_id   = var.msg91_dlt_te_id
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


