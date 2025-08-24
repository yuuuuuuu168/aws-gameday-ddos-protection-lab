# Resource Management Module Outputs

output "cleanup_lambda_function_name" {
  description = "Name of the cleanup Lambda function"
  value       = var.auto_cleanup_enabled ? aws_lambda_function.cleanup_function[0].function_name : null
}

output "cleanup_lambda_function_arn" {
  description = "ARN of the cleanup Lambda function"
  value       = var.auto_cleanup_enabled ? aws_lambda_function.cleanup_function[0].arn : null
}

output "cleanup_schedule_rule_name" {
  description = "Name of the CloudWatch Events rule for cleanup schedule"
  value       = var.auto_cleanup_enabled ? aws_cloudwatch_event_rule.cleanup_schedule[0].name : null
}

output "cleanup_notifications_topic_arn" {
  description = "ARN of the SNS topic for cleanup notifications"
  value       = var.enable_cleanup_notifications ? aws_sns_topic.cleanup_notifications[0].arn : null
}

output "resource_expiration_date" {
  description = "Calculated expiration date for resources"
  value       = local.expiration_date
}

output "lifecycle_tags" {
  description = "Common lifecycle management tags"
  value       = local.lifecycle_tags
  sensitive   = true
}