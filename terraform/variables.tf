# AWS GameDay DDoS Environment - Variables

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "gameday"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "aws-gameday-ddos"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "security_level" {
  description = <<-EOT
    Security level (1-4) for progressive enhancement:
    - Level 1: No protection (baseline vulnerable state)
    - Level 2: Basic WAF protection enabled
    - Level 3: WAF + Shield Advanced protection
    - Level 4: Full protection with CloudFront + WAF + Shield Advanced
  EOT
  type        = number
  default     = 1

  validation {
    condition     = var.security_level >= 1 && var.security_level <= 4
    error_message = "Security level must be between 1 and 4. Valid levels: 1 (No protection), 2 (Basic WAF), 3 (WAF + Shield), 4 (Full protection with CloudFront)."
  }
}

variable "instance_type" {
  description = "EC2 instance type for cost optimization"
  type        = string
  default     = "t3.micro"
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 7
}

variable "auto_cleanup_enabled" {
  description = "Enable automatic resource cleanup"
  type        = bool
  default     = true
}

variable "budget_limit" {
  description = "Monthly budget limit in USD"
  type        = number
  default     = 50
}

# Attack Simulation Variables
variable "enable_attack_simulation" {
  description = "Enable attack simulation instance"
  type        = bool
  default     = true
}

variable "attack_instance_type" {
  description = "EC2 instance type for attack simulation"
  type        = string
  default     = "t3.small"
}

variable "key_pair_name" {
  description = "EC2 Key Pair name for SSH access to attack simulation instance"
  type        = string
  default     = ""
}

variable "allowed_ssh_cidr_blocks" {
  description = "CIDR blocks allowed to SSH to attack simulation instance"
  type        = list(string)
  default     = ["10.0.0.0/8"]  # VPC内からのみ
}

variable "create_attack_results_bucket" {
  description = "Create S3 bucket for storing attack results"
  type        = bool
  default     = false
}

# Resource Management Variables
variable "resource_expiration_hours" {
  description = "Hours until resources expire and are eligible for cleanup"
  type        = number
  default     = 24
  
  validation {
    condition     = var.resource_expiration_hours > 0 && var.resource_expiration_hours <= 168
    error_message = "Resource expiration hours must be between 1 and 168 (1 week)."
  }
}

variable "cleanup_schedule_expression" {
  description = "CloudWatch Events schedule expression for cleanup (cron or rate)"
  type        = string
  default     = "rate(1 hour)"
  
  validation {
    condition = can(regex("^(rate\\(.*\\)|cron\\(.*\\))$", var.cleanup_schedule_expression))
    error_message = "Schedule expression must be in rate() or cron() format."
  }
}

variable "cleanup_dry_run" {
  description = "Run cleanup in dry-run mode (log actions without executing)"
  type        = bool
  default     = false
}

variable "enable_cleanup_notifications" {
  description = "Enable SNS notifications for cleanup actions"
  type        = bool
  default     = true
}

variable "cost_center" {
  description = "Cost center for resource tagging"
  type        = string
  default     = "learning"
}

variable "resource_owner" {
  description = "Resource owner for tagging"
  type        = string
  default     = "gameday-admin"
}

variable "cleanup_notification_email" {
  description = "Email address for cleanup notifications"
  type        = string
  default     = ""
}

# Cost Monitoring Variables
variable "budget_notification_emails" {
  description = "List of email addresses for budget notifications"
  type        = list(string)
  default     = []
}

variable "cost_anomaly_threshold_usd" {
  description = "Threshold for cost anomaly detection in USD"
  type        = number
  default     = 10
}

variable "daily_cost_threshold_usd" {
  description = "Daily cost threshold for CloudWatch alarm in USD"
  type        = number
  default     = 5
}

variable "enable_cost_optimization" {
  description = "Enable cost optimization Lambda function"
  type        = bool
  default     = false
}