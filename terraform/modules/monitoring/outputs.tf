# Monitoring Module - Outputs

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.security_dashboard.dashboard_name}"
}

output "application_log_group_name" {
  description = "Application log group name"
  value       = aws_cloudwatch_log_group.application.name
}

output "alb_log_group_name" {
  description = "ALB log group name"
  value       = aws_cloudwatch_log_group.alb.name
}

output "waf_log_group_name" {
  description = "WAF log group name"
  value       = aws_cloudwatch_log_group.waf.name
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "guardduty_sns_topic_arn" {
  description = "SNS topic ARN for GuardDuty alerts"
  value       = aws_sns_topic.guardduty_alerts.arn
}

output "budget_name" {
  description = "AWS Budget name for cost monitoring"
  value       = aws_budgets_budget.gameday_budget.name
}

output "cost_alerts_topic_arn" {
  description = "SNS topic ARN for cost alerts"
  value       = aws_sns_topic.cost_alerts.arn
}

output "cost_utilization_dashboard_url" {
  description = "Cost and utilization dashboard URL"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.cost_utilization_dashboard.dashboard_name}"
}

# output "cost_anomaly_detector_arn" {
#   description = "Cost anomaly detector ARN"
#   value       = aws_ce_anomaly_detector.gameday_cost_anomaly.arn
# }

# output "cost_optimizer_function_name" {
#   description = "Cost optimizer Lambda function name"
#   value       = var.enable_cost_optimization ? aws_lambda_function.cost_optimizer[0].function_name : null
# }

output "cloudwatch_agent_instance_profile_name" {
  description = "Instance profile name for CloudWatch agent"
  value       = aws_iam_instance_profile.cloudwatch_agent.name
}

output "cloudwatch_agent_config_parameter_name" {
  description = "SSM parameter name for CloudWatch agent configuration"
  value       = aws_ssm_parameter.cloudwatch_agent_config.name
}