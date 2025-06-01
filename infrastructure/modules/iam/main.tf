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
