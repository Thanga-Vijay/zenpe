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
