# Resource Management Module Variables

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "auto_cleanup_enabled" {
  description = "Enable automatic resource cleanup"
  type        = bool
  default     = true
}

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

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 7
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