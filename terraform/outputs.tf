# AWS GameDay DDoS Environment - Outputs

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.network.vpc_id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.network.private_subnet_ids
}

output "application_url" {
  description = "URL of the vulnerable web application"
  value       = module.compute.application_url
}

output "cloudfront_url" {
  description = "CloudFront distribution URL (if enabled)"
  value       = module.security.cloudfront_url
}

output "attack_simulation_instance_id" {
  description = "Attack simulation instance ID"
  value       = module.attack_simulation.instance_id
}

output "attack_simulation_public_ip" {
  description = "Public IP of the attack simulation instance"
  value       = module.attack_simulation.instance_public_ip
}

output "attack_simulation_ssh_command" {
  description = "SSH command to connect to attack simulation instance"
  value       = module.attack_simulation.ssh_command
}

output "attack_simulation_usage" {
  description = "Usage instructions for attack simulation"
  value       = module.attack_simulation.usage_instructions
}

output "security_level" {
  description = "Current security level configuration"
  value       = var.security_level
}

output "security_features" {
  description = "Enabled security features for current level"
  value       = module.security.security_config
}

output "security_level_description" {
  description = "Description of current security level"
  value = {
    level = var.security_level
    name = {
      1 = "Baseline (No Protection)"
      2 = "Basic WAF Protection"
      3 = "Advanced Protection (WAF + Shield)"
      4 = "Full Protection (CloudFront + WAF + Shield)"
    }[var.security_level]
    features = {
      1 = ["Vulnerable web application", "Basic monitoring"]
      2 = ["WAF with managed rules", "Rate limiting", "SQL injection protection"]
      3 = ["All Level 2 features", "Shield Advanced DDoS protection", "Enhanced monitoring"]
      4 = ["All Level 3 features", "CloudFront CDN", "Global edge protection", "Origin access control"]
    }[var.security_level]
  }
}

output "next_security_level_info" {
  description = "Information about the next security level"
  value = var.security_level < 4 ? {
    next_level = var.security_level + 1
    next_level_name = {
      2 = "Basic WAF Protection"
      3 = "Advanced Protection (WAF + Shield)"
      4 = "Full Protection (CloudFront + WAF + Shield)"
    }[var.security_level + 1]
    upgrade_command = "terraform apply -var=\"security_level=${var.security_level + 1}\""
  } : {
    message = "You are at the maximum security level (4)"
  }
}

output "monitoring_dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = module.monitoring.dashboard_url
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = module.monitoring.guardduty_detector_id
}

output "cost_budget_name" {
  description = "AWS Budget name for cost monitoring"
  value       = module.monitoring.budget_name
}

# Resource Management Outputs
output "cleanup_lambda_function_name" {
  description = "Name of the resource cleanup Lambda function"
  value       = module.resource_management.cleanup_lambda_function_name
}

output "cleanup_schedule_rule_name" {
  description = "Name of the CloudWatch Events rule for cleanup schedule"
  value       = module.resource_management.cleanup_schedule_rule_name
}

output "resource_expiration_date" {
  description = "Calculated expiration date for resources"
  value       = module.resource_management.resource_expiration_date
}

output "cleanup_notifications_topic_arn" {
  description = "ARN of the SNS topic for cleanup notifications"
  value       = module.resource_management.cleanup_notifications_topic_arn
}

# Cost Monitoring Outputs
output "cost_alerts_topic_arn" {
  description = "ARN of the SNS topic for cost alerts"
  value       = module.monitoring.cost_alerts_topic_arn
}

output "cost_utilization_dashboard_url" {
  description = "Cost and utilization dashboard URL"
  value       = module.monitoring.cost_utilization_dashboard_url
}

# output "cost_anomaly_detector_arn" {
#   description = "Cost anomaly detector ARN"
#   value       = module.monitoring.cost_anomaly_detector_arn
# }

# output "cost_optimizer_function_name" {
#   description = "Cost optimizer Lambda function name"
#   value       = module.monitoring.cost_optimizer_function_name
# }

# Security configuration mapping
locals {
  security_configs = {
    1 = {
      waf_enabled        = false
      shield_advanced    = false
      cloudfront_enabled = false
      rate_limit         = 10000
    }
    2 = {
      waf_enabled        = true
      shield_advanced    = false
      cloudfront_enabled = false
      rate_limit         = 5000
    }
    3 = {
      waf_enabled        = true
      shield_advanced    = true
      cloudfront_enabled = false
      rate_limit         = 2000
    }
    4 = {
      waf_enabled        = true
      shield_advanced    = true
      cloudfront_enabled = true
      rate_limit         = 1000
    }
  }
}