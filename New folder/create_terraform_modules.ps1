# PowerShell script to create Terraform modules
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
# VPC MODULE
#############################################
$vpcDir = Join-Path $modulesDir "vpc"
if (!(Test-Path $vpcDir)) {
    New-Item -ItemType Directory -Path $vpcDir -Force | Out-Null
}

# VPC main.tf
$vpcMainTf = @'
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = {
    Name        = "${var.app_name}-vpc-${var.environment}"
    Environment = var.environment
  }
}

# Public subnets
resource "aws_subnet" "public" {
  count = length(var.public_subnets)
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name        = "${var.app_name}-public-subnet-${count.index + 1}"
    Environment = var.environment
  }
}

# Private subnets
resource "aws_subnet" "private" {
  count = length(var.private_subnets)
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnets[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false
  
  tags = {
    Name        = "${var.app_name}-private-subnet-${count.index + 1}"
    Environment = var.environment
  }
}

# Database subnets (for Aurora)
resource "aws_subnet" "database" {
  count = length(var.private_subnets)
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.database_subnets[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false
  
  tags = {
    Name        = "${var.app_name}-database-subnet-${count.index + 1}"
    Environment = var.environment
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name        = "${var.app_name}-igw"
    Environment = var.environment
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  count = length(var.azs)
  vpc   = true
  
  tags = {
    Name        = "${var.app_name}-nat-eip-${count.index + 1}"
    Environment = var.environment
  }
}

# NAT Gateway
resource "aws_nat_gateway" "main" {
  count = length(var.azs)
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.main]
  
  tags = {
    Name        = "${var.app_name}-nat-${count.index + 1}"
    Environment = var.environment
  }
}

# Route table for public subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  
  tags = {
    Name        = "${var.app_name}-public-route-table"
    Environment = var.environment
  }
}

# Route tables for private subnets
resource "aws_route_table" "private" {
  count = length(var.azs)
  
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }
  
  tags = {
    Name        = "${var.app_name}-private-route-table-${count.index + 1}"
    Environment = var.environment
  }
}

# Route table association for public subnets
resource "aws_route_table_association" "public" {
  count = length(var.public_subnets)
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Route table association for private subnets
resource "aws_route_table_association" "private" {
  count = length(var.private_subnets)
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Security group for common access
resource "aws_security_group" "common" {
  name        = "${var.app_name}-common-sg"
  description = "Common security group for ${var.app_name}"
  vpc_id      = aws_vpc.main.id
  
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
'@

Set-FileContent -Path (Join-Path $vpcDir "main.tf") -Content $vpcMainTf

# VPC variables.tf
$vpcVariablesTf = @'
variable "app_name" {
  description = "Name of the application"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
}

variable "azs" {
  description = "Availability zones to use"
  type        = list(string)
}

variable "private_subnets" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
}

variable "public_subnets" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
}

variable "database_subnets" {
  description = "CIDR blocks for database subnets"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
}
'@

Set-FileContent -Path (Join-Path $vpcDir "variables.tf") -Content $vpcVariablesTf

# VPC outputs.tf
$vpcOutputsTf = @'
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "database_subnet_ids" {
  description = "IDs of the database subnets"
  value       = aws_subnet.database[*].id
}

output "nat_gateway_ids" {
  description = "IDs of the NAT gateways"
  value       = aws_nat_gateway.main[*].id
}

output "common_security_group_id" {
  description = "ID of the common security group"
  value       = aws_security_group.common.id
}
'@

Set-FileContent -Path (Join-Path $vpcDir "outputs.tf") -Content $vpcOutputsTf

#############################################
# DATABASE MODULE
#############################################
$dbDir = Join-Path $modulesDir "database"
if (!(Test-Path $dbDir)) {
    New-Item -ItemType Directory -Path $dbDir -Force | Out-Null
}

# Database main.tf
$dbMainTf = @'
resource "aws_db_subnet_group" "main" {
  name        = "${var.app_name}-db-subnet-group-${var.environment}"
  description = "DB subnet group for ${var.app_name}"
  subnet_ids  = var.subnet_ids
  
  tags = {
    Name        = "${var.app_name}-db-subnet-group"
    Environment = var.environment
  }
}

resource "aws_security_group" "db" {
  name        = "${var.app_name}-db-sg"
  description = "Security group for ${var.app_name} database"
  vpc_id      = var.vpc_id
  
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.app_security_group_id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.app_name}-db-sg"
    Environment = var.environment
  }
}

resource "aws_rds_cluster" "aurora" {
  cluster_identifier      = "${var.app_name}-aurora-${var.environment}"
  engine                  = "aurora-postgresql"
  engine_version          = var.engine_version
  database_name           = var.database_name
  master_username         = var.master_username
  master_password         = var.master_password
  backup_retention_period = 7
  preferred_backup_window = "03:00-04:00"
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.db.id]
  skip_final_snapshot     = true
  
  tags = {
    Name        = "${var.app_name}-aurora-cluster"
    Environment = var.environment
  }
}

resource "aws_rds_cluster_instance" "aurora_instances" {
  count                = var.instance_count
  identifier           = "${var.app_name}-aurora-instance-${count.index + 1}-${var.environment}"
  cluster_identifier   = aws_rds_cluster.aurora.id
  instance_class       = var.instance_class
  engine               = "aurora-postgresql"
  engine_version       = var.engine_version
  db_subnet_group_name = aws_db_subnet_group.main.name
  
  tags = {
    Name        = "${var.app_name}-aurora-instance-${count.index + 1}"
    Environment = var.environment
  }
}
'@

Set-FileContent -Path (Join-Path $dbDir "main.tf") -Content $dbMainTf

# Database variables.tf
$dbVariablesTf = @'
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

variable "subnet_ids" {
  description = "IDs of the subnets to deploy the database in"
  type        = list(string)
}

variable "app_security_group_id" {
  description = "ID of the application security group"
  type        = string
  default     = ""
}

variable "instance_class" {
  description = "Instance class for Aurora instances"
  type        = string
  default     = "db.t3.small"
}

variable "instance_count" {
  description = "Number of Aurora instances"
  type        = number
  default     = 2
}

variable "engine_version" {
  description = "Aurora PostgreSQL engine version"
  type        = string
  default     = "13.7"
}

variable "database_name" {
  description = "Name of the database"
  type        = string
}

variable "master_username" {
  description = "Master username for the database"
  type        = string
}

variable "master_password" {
  description = "Master password for the database"
  type        = string
  sensitive   = true
}
'@

Set-FileContent -Path (Join-Path $dbDir "variables.tf") -Content $dbVariablesTf

# Database outputs.tf
$dbOutputsTf = @'
output "endpoint" {
  description = "Endpoint of the Aurora cluster"
  value       = aws_rds_cluster.aurora.endpoint
}

output "reader_endpoint" {
  description = "Reader endpoint of the Aurora cluster"
  value       = aws_rds_cluster.aurora.reader_endpoint
}

output "cluster_id" {
  description = "ID of the Aurora cluster"
  value       = aws_rds_cluster.aurora.id
}

output "security_group_id" {
  description = "ID of the database security group"
  value       = aws_security_group.db.id
}
'@

Set-FileContent -Path (Join-Path $dbDir "outputs.tf") -Content $dbOutputsTf

#############################################
# REDIS MODULE
#############################################
$redisDir = Join-Path $modulesDir "redis"
if (!(Test-Path $redisDir)) {
    New-Item -ItemType Directory -Path $redisDir -Force | Out-Null
}

# Redis main.tf
$redisMainTf = @'
resource "aws_elasticache_subnet_group" "main" {
  name        = "${var.app_name}-redis-subnet-group-${var.environment}"
  description = "Redis subnet group for ${var.app_name}"
  subnet_ids  = var.subnet_ids
}

resource "aws_security_group" "redis" {
  name        = "${var.app_name}-redis-sg"
  description = "Security group for ${var.app_name} Redis"
  vpc_id      = var.vpc_id
  
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [var.app_security_group_id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.app_name}-redis-sg"
    Environment = var.environment
  }
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id          = "${var.app_name}-redis-${var.environment}"
  description                   = "Redis cluster for ${var.app_name}"
  node_type                     = var.node_type
  num_cache_clusters            = var.num_cache_clusters
  parameter_group_name          = "default.redis6.x"
  port                          = 6379
  subnet_group_name             = aws_elasticache_subnet_group.main.name
  security_group_ids            = [aws_security_group.redis.id]
  automatic_failover_enabled    = var.automatic_failover_enabled
  at_rest_encryption_enabled    = true
  transit_encryption_enabled    = true
  
  tags = {
    Name        = "${var.app_name}-redis"
    Environment = var.environment
  }
}
'@

Set-FileContent -Path (Join-Path $redisDir "main.tf") -Content $redisMainTf

# Redis variables.tf
$redisVariablesTf = @'
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

variable "subnet_ids" {
  description = "IDs of the subnets to deploy Redis in"
  type        = list(string)
}

variable "app_security_group_id" {
  description = "ID of the application security group"
  type        = string
  default     = ""
}

variable "node_type" {
  description = "Node type for Redis"
  type        = string
  default     = "cache.t3.small"
}

variable "num_cache_clusters" {
  description = "Number of Redis cache clusters"
  type        = number
  default     = 2
}

variable "automatic_failover_enabled" {
  description = "Enable automatic failover"
  type        = bool
  default     = true
}

variable "engine_version" {
  description = "Redis engine version"
  type        = string
  default     = "6.x"
}
'@

Set-FileContent -Path (Join-Path $redisDir "variables.tf") -Content $redisVariablesTf

# Redis outputs.tf
$redisOutputsTf = @'
output "endpoint" {
  description = "Primary endpoint for Redis"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "reader_endpoint" {
  description = "Reader endpoint for Redis"
  value       = aws_elasticache_replication_group.redis.reader_endpoint_address
}

output "security_group_id" {
  description = "ID of the Redis security group"
  value       = aws_security_group.redis.id
}
'@

Set-FileContent -Path (Join-Path $redisDir "outputs.tf") -Content $redisOutputsTf

#############################################
# ECS MODULE
#############################################
$ecsDir = Join-Path $modulesDir "ecs"
if (!(Test-Path $ecsDir)) {
    New-Item -ItemType Directory -Path $ecsDir -Force | Out-Null
}

# ECS main.tf
$ecsMainTf = @'
resource "aws_ecs_cluster" "main" {
  name = "${var.app_name}-cluster-${var.environment}"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  
  tags = {
    Name        = "${var.app_name}-ecs-cluster"
    Environment = var.environment
  }
}

resource "aws_security_group" "ecs" {
  name        = "${var.app_name}-ecs-sg"
  description = "Security group for ${var.app_name} ECS services"
  vpc_id      = var.vpc_id
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.app_name}-ecs-sg"
    Environment = var.environment
  }
}

# Create CloudWatch Log Group for ECS services
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.app_name}-${var.environment}"
  retention_in_days = 30
  
  tags = {
    Name        = "${var.app_name}-ecs-logs"
    Environment = var.environment
  }
}

# Create IAM role for ECS task execution
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

# Create IAM role for ECS tasks
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
'@

Set-FileContent -Path (Join-Path $ecsDir "main.tf") -Content $ecsMainTf

# ECS variables.tf
$ecsVariablesTf = @'
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

variable "subnet_ids" {
  description = "IDs of the subnets to deploy ECS tasks in"
  type        = list(string)
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-1"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}
'@

Set-FileContent -Path (Join-Path $ecsDir "variables.tf") -Content $ecsVariablesTf

# ECS outputs.tf
$ecsOutputsTf = @'
output "cluster_id" {
  description = "ID of the ECS cluster"
  value       = aws_ecs_cluster.main.id
}

output "cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "security_group_id" {
  description = "ID of the ECS security group"
  value       = aws_security_group.ecs.id
}

output "log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.ecs.name
}

output "task_execution_role_arn" {
  description = "ARN of the ECS task execution role"
  value       = aws_iam_role.ecs_task_execution_role.arn
}

output "task_role_arn" {
  description = "ARN of the ECS task role"
  value       = aws_iam_role.ecs_task_role.arn
}
'@

Set-FileContent -Path (Join-Path $ecsDir "outputs.tf") -Content $ecsOutputsTf

#############################################
# ECS SERVICE MODULE
#############################################
$ecsServiceDir = Join-Path $modulesDir "ecs-service"
if (!(Test-Path $ecsServiceDir)) {
    New-Item -ItemType Directory -Path $ecsServiceDir -Force | Out-Null
}

# ECS Service main.tf (continued)
$ecsServiceMainTf = @'
resource "aws_ecs_task_definition" "service" {
  family                   = "${var.app_name}-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = var.task_execution_role_arn
  task_role_arn            = var.task_role_arn
  
  container_definitions = jsonencode([
    {
      name      = "${var.app_name}-container"
      image     = var.container_image
      essential = true
      
      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]
      
      environment = var.environment_variables
      
      secrets = var.secrets
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = var.app_name
        }
      }
    }
  ])
  
  tags = {
    Name        = "${var.app_name}-task-definition"
    Environment = var.environment
  }
}

resource "aws_security_group" "service" {
  name        = "${var.app_name}-service-sg-${var.environment}"
  description = "Security group for ${var.app_name} service"
  vpc_id      = var.vpc_id
  
  ingress {
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [var.alb_security_group_id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.app_name}-service-sg"
    Environment = var.environment
  }
}

resource "aws_lb_target_group" "service" {
  name        = "${var.app_name}-tg-${var.environment}"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  
  health_check {
    enabled             = true
    interval            = 30
    path                = var.health_check_path
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    matcher             = "200"
  }
  
  tags = {
    Name        = "${var.app_name}-target-group"
    Environment = var.environment
  }
}

resource "aws_lb_listener_rule" "service" {
  listener_arn = var.alb_listener_arn
  priority     = var.listener_priority
  
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service.arn
  }
  
  condition {
    path_pattern {
      values = ["/${var.path_pattern}*"]
    }
  }
}

resource "aws_ecs_service" "service" {
  name            = "${var.app_name}-service-${var.environment}"
  cluster         = var.ecs_cluster_id
  task_definition = aws_ecs_task_definition.service.arn
  launch_type     = "FARGATE"
  desired_count   = var.desired_count
  
  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = false
  }
  
  load_balancer {
    target_group_arn = aws_lb_target_group.service.arn
    container_name   = "${var.app_name}-container"
    container_port   = var.container_port
  }
  
  lifecycle {
    ignore_changes = [desired_count]
  }
  
  tags = {
    Name        = "${var.app_name}-ecs-service"
    Environment = var.environment
  }
}

# Auto Scaling for the service
resource "aws_appautoscaling_target" "service" {
  max_capacity       = var.max_capacity
  min_capacity       = var.min_capacity
  resource_id        = "service/${var.ecs_cluster_name}/${aws_ecs_service.service.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.app_name}-cpu-autoscaling-${var.environment}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.service.resource_id
  scalable_dimension = aws_appautoscaling_target.service.scalable_dimension
  service_namespace  = aws_appautoscaling_target.service.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    
    target_value       = var.target_cpu_utilization
    scale_in_cooldown  = 300
    scale_out_cooldown = 300
  }
}

resource "aws_appautoscaling_policy" "memory" {
  name               = "${var.app_name}-memory-autoscaling-${var.environment}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.service.resource_id
  scalable_dimension = aws_appautoscaling_target.service.scalable_dimension
  service_namespace  = aws_appautoscaling_target.service.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    
    target_value       = var.target_memory_utilization
    scale_in_cooldown  = 300
    scale_out_cooldown = 300
  }
}
'@

Set-FileContent -Path (Join-Path $ecsServiceDir "main.tf") -Content $ecsServiceMainTf

# ECS Service variables.tf
$ecsServiceVariablesTf = @'
variable "app_name" {
  description = "Name of the application"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "ecs_cluster_id" {
  description = "ID of the ECS cluster"
  type        = string
}

variable "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC"
  type        = string
}

variable "subnet_ids" {
  description = "IDs of the subnets to deploy the service in"
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "ID of the ALB security group"
  type        = string
}

variable "alb_listener_arn" {
  description = "ARN of the ALB listener"
  type        = string
}

variable "listener_priority" {
  description = "Priority of the listener rule"
  type        = number
}

variable "path_pattern" {
  description = "Path pattern for the listener rule"
  type        = string
}

variable "container_port" {
  description = "Port exposed by the container"
  type        = number
}

variable "container_image" {
  description = "Docker image to use for the container"
  type        = string
}

variable "task_execution_role_arn" {
  description = "ARN of the task execution role"
  type        = string
}

variable "task_role_arn" {
  description = "ARN of the task role"
  type        = string
}

variable "desired_count" {
  description = "Desired count of containers"
  type        = number
  default     = 2
}

variable "cpu" {
  description = "CPU units for the task"
  type        = number
  default     = 256
}

variable "memory" {
  description = "Memory for the task in MB"
  type        = number
  default     = 512
}

variable "environment_variables" {
  description = "Environment variables for the container"
  type        = list(object({
    name  = string
    value = string
  }))
  default     = []
}

variable "secrets" {
  description = "Secrets for the container"
  type        = list(object({
    name      = string
    valueFrom = string
  }))
  default     = []
}

variable "health_check_path" {
  description = "Path for health checks"
  type        = string
  default     = "/health"
}

variable "log_group_name" {
  description = "Name of the CloudWatch log group"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-1"
}

variable "max_capacity" {
  description = "Maximum capacity for auto scaling"
  type        = number
  default     = 4
}

variable "min_capacity" {
  description = "Minimum capacity for auto scaling"
  type        = number
  default     = 2
}

variable "target_cpu_utilization" {
  description = "Target CPU utilization for auto scaling"
  type        = number
  default     = 70
}

variable "target_memory_utilization" {
  description = "Target memory utilization for auto scaling"
  type        = number
  default     = 70
}
'@

Set-FileContent -Path (Join-Path $ecsServiceDir "variables.tf") -Content $ecsServiceVariablesTf

# ECS Service outputs.tf
$ecsServiceOutputsTf = @'
output "service_id" {
  description = "ID of the ECS service"
  value       = aws_ecs_service.service.id
}

output "service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.service.name
}

output "service_url" {
  description = "URL of the service"
  value       = "http://${var.app_name}.${var.environment}.internal:${var.container_port}"
}

output "target_group_arn" {
  description = "ARN of the target group"
  value       = aws_lb_target_group.service.arn
}

output "security_group_id" {
  description = "ID of the service security group"
  value       = aws_security_group.service.id
}
'@

Set-FileContent -Path (Join-Path $ecsServiceDir "outputs.tf") -Content $ecsServiceOutputsTf

#############################################
# API GATEWAY MODULE
#############################################
$apiGatewayDir = Join-Path $modulesDir "api-gateway"
if (!(Test-Path $apiGatewayDir)) {
    New-Item -ItemType Directory -Path $apiGatewayDir -Force | Out-Null
}

# API Gateway main.tf
$apiGatewayMainTf = @'
# ALB for API Gateway
resource "aws_security_group" "alb" {
  name        = "${var.app_name}-alb-sg-${var.environment}"
  description = "Security group for ${var.app_name} ALB"
  vpc_id      = var.vpc_id
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.app_name}-alb-sg"
    Environment = var.environment
  }
}

resource "aws_lb" "main" {
  name               = "${var.app_name}-alb-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
  
  enable_deletion_protection = var.environment == "prod" ? true : false
  
  tags = {
    Name        = "${var.app_name}-alb"
    Environment = var.environment
  }
}

# HTTP listener - redirect to HTTPS
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type = "redirect"
    
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# HTTPS listener
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn
  
  default_action {
    type = "fixed-response"
    
    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }
}

# Internal ALB for private services
resource "aws_security_group" "internal_alb" {
  name        = "${var.app_name}-internal-alb-sg-${var.environment}"
  description = "Security group for ${var.app_name} internal ALB"
  vpc_id      = var.vpc_id
  
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.app_name}-internal-alb-sg"
    Environment = var.environment
  }
}

resource "aws_lb" "internal" {
  name               = "${var.app_name}-internal-alb-${var.environment}"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.internal_alb.id]
  subnets            = var.private_subnet_ids
  
  tags = {
    Name        = "${var.app_name}-internal-alb"
    Environment = var.environment
  }
}

resource "aws_lb_listener" "internal" {
  load_balancer_arn = aws_lb.internal.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type = "fixed-response"
    
    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }
}

# API Gateway VPC Link
resource "aws_apigatewayv2_vpc_link" "main" {
  name               = "${var.app_name}-vpc-link-${var.environment}"
  security_group_ids = [aws_security_group.alb.id]
  subnet_ids         = var.private_subnet_ids
  
  tags = {
    Name        = "${var.app_name}-vpc-link"
    Environment = var.environment
  }
}

# API Gateway HTTP API
resource "aws_apigatewayv2_api" "main" {
  name          = "${var.app_name}-api-${var.environment}"
  protocol_type = "HTTP"
  
  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["*"]
    allow_headers = ["*"]
    max_age       = 300
  }
  
  tags = {
    Name        = "${var.app_name}-api"
    Environment = var.environment
  }
}

# API Gateway Stage
resource "aws_apigatewayv2_stage" "main" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = var.environment
  auto_deploy = true
  
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      integrationError = "$context.integrationErrorMessage"
    })
  }
  
  tags = {
    Name        = "${var.app_name}-stage"
    Environment = var.environment
  }
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.app_name}-${var.environment}"
  retention_in_days = 30
  
  tags = {
    Name        = "${var.app_name}-api-gateway-logs"
    Environment = var.environment
  }
}

# Create integrations for each service
resource "aws_apigatewayv2_integration" "service" {
  for_each = { for i in var.integrations : i.name => i }
  
  api_id             = aws_apigatewayv2_api.main.id
  integration_type   = "HTTP_PROXY"
  integration_uri    = each.value.target_url
  integration_method = "ANY"
  connection_type    = "VPC_LINK"
  connection_id      = aws_apigatewayv2_vpc_link.main.id
}

# Create routes for each service
resource "aws_apigatewayv2_route" "service" {
  for_each = { for i in var.integrations : i.name => i }
  
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "ANY /${each.value.base_path}/{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.service[each.key].id}"
}

# Create domain name mapping if domain is provided
resource "aws_apigatewayv2_domain_name" "main" {
  count = var.domain_name != "" ? 1 : 0
  
  domain_name = var.domain_name
  
  domain_name_configuration {
    certificate_arn = var.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
  
  tags = {
    Name        = "${var.app_name}-domain"
    Environment = var.environment
  }
}

resource "aws_apigatewayv2_api_mapping" "main" {
  count = var.domain_name != "" ? 1 : 0
  
  api_id      = aws_apigatewayv2_api.main.id
  domain_name = aws_apigatewayv2_domain_name.main[0].id
  stage       = aws_apigatewayv2_stage.main.id
}

# Route53 record for the API Gateway domain
resource "aws_route53_record" "main" {
  count = var.domain_name != "" && var.hosted_zone_id != "" ? 1 : 0
  
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  
  alias {
    name                   = aws_apigatewayv2_domain_name.main[0].domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.main[0].domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
'@

Set-FileContent -Path (Join-Path $apiGatewayDir "main.tf") -Content $apiGatewayMainTf

# API Gateway variables.tf
$apiGatewayVariablesTf = @'
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

variable "public_subnet_ids" {
  description = "IDs of the public subnets for the ALB"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "IDs of the private subnets for the internal ALB"
  type        = list(string)
}

variable "certificate_arn" {
  description = "ARN of the SSL certificate"
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Domain name for the API"
  type        = string
  default     = ""
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID"
  type        = string
  default     = ""
}

variable "integrations" {
  description = "List of service integrations"
  type        = list(object({
    name       = string
    target_url = string
    base_path  = string
  }))
}
'@

Set-FileContent -Path (Join-Path $apiGatewayDir "variables.tf") -Content $apiGatewayVariablesTf

# API Gateway outputs.tf
$apiGatewayOutputsTf = @'
output "api_id" {
  description = "ID of the API Gateway"
  value       = aws_apigatewayv2_api.main.id
}

output "api_url" {
  description = "URL of the API Gateway"
  value       = aws_apigatewayv2_stage.main.invoke_url
}

output "domain_name" {
  description = "Domain name of the API Gateway"
  value       = var.domain_name != "" ? var.domain_name : null
}

output "alb_dns_name" {
  description = "DNS name of the ALB"
  value       = aws_lb.main.dns_name
}

output "internal_alb_dns_name" {
  description = "DNS name of the internal ALB"
  value       = aws_lb.internal.dns_name
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb.id
}

output "internal_alb_security_group_id" {
  description = "ID of the internal ALB security group"
  value       = aws_security_group.internal_alb.id
}

output "vpc_link_id" {
  description = "ID of the VPC Link"
  value       = aws_apigatewayv2_vpc_link.main.id
}
'@

Set-FileContent -Path (Join-Path $apiGatewayDir "outputs.tf") -Content $apiGatewayOutputsTf

Write-Host "All Terraform modules have been successfully created!"
Write-Host "You can find the modules in: $modulesDir"