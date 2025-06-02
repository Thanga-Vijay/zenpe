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
  listener_arn = var.alb_listener_arn != "" ? var.alb_listener_arn : null
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

# Add environment variables for KYC service here if needed, following the supported aws_ecs_task_definition format.

# Enhanced security group rules
resource "aws_security_group_rule" "kyc_service_email" {
  type              = "egress"
  from_port         = 587
  to_port           = 587
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.service.id
  description       = "SMTP Access for Email Notifications"
}
