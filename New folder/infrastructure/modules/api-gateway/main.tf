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
  count             = var.certificate_arn != "" ? 1 : 0
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
