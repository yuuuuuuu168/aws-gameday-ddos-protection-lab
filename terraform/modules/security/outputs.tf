# Security Module - Outputs

output "app_security_group_id" {
  description = "ID of the application security group"
  value       = aws_security_group.app.id
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb.id
}

output "attack_security_group_id" {
  description = "ID of the attack simulation security group"
  value       = aws_security_group.attack_simulation.id
}

output "database_security_group_id" {
  description = "ID of the database security group"
  value       = aws_security_group.database.id
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = local.current_config.waf_enabled ? aws_wafv2_web_acl.main[0].arn : null
}

output "waf_web_acl_name" {
  description = "Name of the WAF Web ACL"
  value       = local.current_config.waf_enabled ? aws_wafv2_web_acl.main[0].name : null
}

output "waf_web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = local.current_config.waf_enabled ? aws_wafv2_web_acl.main[0].id : null
}

output "security_level" {
  description = "Current security level"
  value       = var.security_level
}

output "security_config" {
  description = "Current security configuration"
  value       = local.current_config
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = local.current_config.cloudfront_enabled ? aws_cloudfront_distribution.main[0].id : null
}

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = local.current_config.cloudfront_enabled ? aws_cloudfront_distribution.main[0].domain_name : null
}

output "cloudfront_url" {
  description = "CloudFront distribution URL"
  value       = local.current_config.cloudfront_enabled ? "https://${aws_cloudfront_distribution.main[0].domain_name}" : null
}

output "cloudfront_waf_web_acl_arn" {
  description = "ARN of the CloudFront WAF Web ACL"
  value       = local.current_config.cloudfront_enabled ? aws_wafv2_web_acl.cloudfront[0].arn : null
}