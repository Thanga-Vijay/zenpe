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
