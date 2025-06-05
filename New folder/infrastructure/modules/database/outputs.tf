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
