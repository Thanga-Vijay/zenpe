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
