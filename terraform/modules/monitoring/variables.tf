# Monitoring Module - Variables

variable "vpc_id" {
  description = "ID of the VPC"
  type        = string
}

variable "alb_arn_suffix" {
  description = "ARN suffix of the Application Load Balancer"
  type        = string
}

variable "waf_web_acl_name" {
  description = "Name of the WAF Web ACL"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "security_level" {
  description = "Security level (1-4) for progressive enhancement"
  type        = number
}

variable "alb_logs_bucket_name" {
  description = "Name of the S3 bucket for ALB access logs"
  type        = string
  default     = ""
}

# Cost Monitoring Variables
variable "budget_limit_usd" {
  description = "Monthly budget limit in USD"
  type        = number
  default     = 50
}

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
  default     = true
}