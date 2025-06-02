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

output "https_listener_arn" {
  description = "ARN of the HTTPS listener for the ALB"
  value       = aws_lb_listener.https[0].arn
}
