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
