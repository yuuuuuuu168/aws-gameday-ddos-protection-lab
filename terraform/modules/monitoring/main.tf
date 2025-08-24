# Monitoring Module - Main Configuration

# SNS Topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "${var.project_name}-guardduty-alerts"

  tags = {
    Name        = "${var.project_name}-guardduty-alerts"
    Environment = var.environment
  }
}

# SNS Topic Policy for GuardDuty
resource "aws_sns_topic_policy" "guardduty_alerts" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGuardDutyToPublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.guardduty_alerts.arn
      }
    ]
  })
}

# GuardDuty Detector
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name        = "${var.project_name}-guardduty-detector"
    Environment = var.environment
  }
}

# CloudWatch Event Rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project_name}-guardduty-findings"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = {
    Name        = "${var.project_name}-guardduty-findings-rule"
    Environment = var.environment
  }
}

# CloudWatch Event Target for SNS
resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "GuardDutySNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      region      = "$.detail.region"
      accountId   = "$.detail.accountId"
      description = "$.detail.description"
    }
    input_template = jsonencode({
      "GuardDuty Alert" = {
        "Severity"    = "<severity>"
        "Type"        = "<type>"
        "Region"      = "<region>"
        "Account ID"  = "<accountId>"
        "Description" = "<description>"
      }
    })
  }
}
# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "application" {
  name              = "/aws/gameday/${var.project_name}/application"
  retention_in_days = 7 # Cost optimization

  tags = {
    Name        = "${var.project_name}-application-logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "alb" {
  name              = "/aws/gameday/${var.project_name}/alb"
  retention_in_days = 7 # Cost optimization

  tags = {
    Name        = "${var.project_name}-alb-logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "/aws/gameday/${var.project_name}/waf"
  retention_in_days = 7 # Cost optimization

  tags = {
    Name        = "${var.project_name}-waf-logs"
    Environment = var.environment
  }
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "security_dashboard" {
  dashboard_name = "${var.project_name}-security-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_arn_suffix],
            [".", "TargetResponseTime", ".", "."],
            [".", "HTTPCode_Target_2XX_Count", ".", "."],
            [".", "HTTPCode_Target_4XX_Count", ".", "."],
            [".", "HTTPCode_Target_5XX_Count", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Application Load Balancer Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", "*"],
            ["AWS/ApplicationELB", "ActiveConnectionCount", "LoadBalancer", var.alb_arn_suffix]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "WAF Security Metrics"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 24
        height = 6

        properties = {
          query   = "SOURCE '${aws_cloudwatch_log_group.application.name}' | fields @timestamp, @message | sort @timestamp desc | limit 100"
          region  = data.aws_region.current.name
          title   = "Recent Application Logs"
        }
      }
    ]
  })
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "${var.project_name}-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors application error rate"
  alarm_actions       = [aws_sns_topic.guardduty_alerts.arn]

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  tags = {
    Name        = "${var.project_name}-high-error-rate-alarm"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "suspicious_request_rate" {
  alarm_name          = "${var.project_name}-suspicious-request-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "RequestCount"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1000"
  alarm_description   = "This metric monitors for unusually high request rates"
  alarm_actions       = [aws_sns_topic.guardduty_alerts.arn]

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  tags = {
    Name        = "${var.project_name}-suspicious-request-rate-alarm"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "waf_blocked_requests" {
  alarm_name          = "${var.project_name}-waf-blocked-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "50"
  alarm_description   = "This metric monitors WAF blocked requests indicating potential attacks"
  alarm_actions       = [aws_sns_topic.guardduty_alerts.arn]

  dimensions = {
    WebACL = var.waf_web_acl_name
    Region = data.aws_region.current.name
    Rule   = "ALL"
  }

  tags = {
    Name        = "${var.project_name}-waf-blocked-requests-alarm"
    Environment = var.environment
  }
}

# Data source for current region
data "aws_region" "current" {}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# AWS Budget for cost monitoring
resource "aws_budgets_budget" "gameday_budget" {
  name         = "${var.project_name}-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.budget_limit_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  time_period_start = formatdate("YYYY-MM-01_00:00", timestamp())

  cost_filter {
    name   = "Service"
    values = ["Amazon Elastic Compute Cloud - Compute", "Amazon Elastic Load Balancing"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = var.budget_notification_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.budget_notification_emails
  }

  tags = {
    Name        = "${var.project_name}-budget"
    Environment = var.environment
  }
}

# Cost Anomaly Detection - Commented out as resource type not supported
# resource "aws_ce_anomaly_detector" "gameday_cost_anomaly" {
#   name         = "${var.project_name}-cost-anomaly-detector"
#   monitor_type = "DIMENSIONAL"
#
#   specification = jsonencode({
#     Dimension = "SERVICE"
#     MatchOptions = ["EQUALS"]
#     Values = ["Amazon Elastic Compute Cloud - Compute", "Amazon Simple Storage Service", "Amazon CloudWatch"]
#   })
#
#   tags = {
#     Name        = "${var.project_name}-cost-anomaly-detector"
#     Environment = var.environment
#   }
# }

# Cost Anomaly Subscription - Commented out due to dependency issues
# resource "aws_ce_anomaly_subscription" "gameday_cost_anomaly_subscription" {
#   name      = "${var.project_name}-cost-anomaly-subscription"
#   frequency = "DAILY"
#   
#   monitor_arn_list = [
#     aws_ce_anomaly_detector.gameday_cost_anomaly.arn
#   ]
#   
#   subscriber {
#     type    = "EMAIL"
#     address = length(var.budget_notification_emails) > 0 ? var.budget_notification_emails[0] : "admin@example.com"
#   }
#
#   threshold_expression {
#     and {
#       dimension {
#         key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
#         values        = [tostring(var.cost_anomaly_threshold_usd)]
#         match_options = ["GREATER_THAN_OR_EQUAL"]
#       }
#     }
#   }
#
#   tags = {
#     Name        = "${var.project_name}-cost-anomaly-subscription"
#     Environment = var.environment
#   }
# }

# SNS Topic for cost alerts
resource "aws_sns_topic" "cost_alerts" {
  name = "${var.project_name}-cost-alerts"

  tags = {
    Name        = "${var.project_name}-cost-alerts"
    Environment = var.environment
  }
}

# SNS Topic Subscription for cost alerts
resource "aws_sns_topic_subscription" "cost_alerts_email" {
  count = length(var.budget_notification_emails)
  
  topic_arn = aws_sns_topic.cost_alerts.arn
  protocol  = "email"
  endpoint  = var.budget_notification_emails[count.index]
}

# CloudWatch Metric for estimated charges
resource "aws_cloudwatch_metric_alarm" "estimated_charges" {
  alarm_name          = "${var.project_name}-estimated-charges"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "EstimatedCharges"
  namespace           = "AWS/Billing"
  period              = "86400" # 24 hours
  statistic           = "Maximum"
  threshold           = var.daily_cost_threshold_usd
  alarm_description   = "This metric monitors estimated daily charges"
  alarm_actions       = [aws_sns_topic.cost_alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    Currency = "USD"
  }

  tags = {
    Name        = "${var.project_name}-estimated-charges-alarm"
    Environment = var.environment
  }
}

# Resource utilization monitoring dashboard
resource "aws_cloudwatch_dashboard" "cost_utilization_dashboard" {
  dashboard_name = "${var.project_name}-cost-utilization-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Billing", "EstimatedCharges", "Currency", "USD"],
            ["AWS/EC2", "CPUUtilization", "InstanceId", "i-*"],
            ["AWS/ApplicationELB", "ActiveConnectionCount", "LoadBalancer", var.alb_arn_suffix]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1" # Billing metrics are only available in us-east-1
          title   = "Cost and Resource Utilization"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/S3", "BucketSizeBytes", "BucketName", "*", "StorageType", "StandardStorage"],
            ["AWS/Logs", "IncomingBytes", "LogGroupName", aws_cloudwatch_log_group.application.name],
            ["AWS/Logs", "IncomingBytes", "LogGroupName", aws_cloudwatch_log_group.alb.name],
            ["AWS/Logs", "IncomingBytes", "LogGroupName", aws_cloudwatch_log_group.waf.name]
          ]
          view    = "timeSeries"
          stacked = true
          region  = data.aws_region.current.name
          title   = "Storage and Log Usage"
          period  = 3600
          stat    = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6

        properties = {
          metrics = [
            ["AWS/CloudFront", "Requests", "DistributionId", "*"],
            ["AWS/EC2", "CPUUtilization", "InstanceId", "*"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Security Service Usage"
          period  = 3600
          stat    = "Sum"
        }
      }
    ]
  })
}

# Lambda function for cost optimization recommendations - Temporarily disabled
# resource "aws_lambda_function" "cost_optimizer" {
#   count = var.enable_cost_optimization ? 1 : 0
#   
#   filename         = data.archive_file.cost_optimizer_zip[0].output_path
#   function_name    = "${var.project_name}-cost-optimizer"
#   role            = aws_iam_role.cost_optimizer_role[0].arn
#   handler         = "cost_optimizer.lambda_handler"
#   source_code_hash = data.archive_file.cost_optimizer_zip[0].output_base64sha256
#   runtime         = "python3.9"
#   timeout         = 300
#
#   environment {
#     variables = {
#       PROJECT_NAME = var.project_name
#       ENVIRONMENT  = var.environment
#       SNS_TOPIC_ARN = aws_sns_topic.cost_alerts.arn
#     }
#   }
#
#   tags = {
#     Name        = "${var.project_name}-cost-optimizer"
#     Environment = var.environment
#   }
# }

# IAM Role for cost optimizer Lambda - Temporarily disabled
# resource "aws_iam_role" "cost_optimizer_role" {
#   count = var.enable_cost_optimization ? 1 : 0
#   
#   name = "${var.project_name}-cost-optimizer-role"
#
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRole"
#         Effect = "Allow"
#         Principal = {
#           Service = "lambda.amazonaws.com"
#         }
#       }
#     ]
#   })
#
#   tags = {
#     Name        = "${var.project_name}-cost-optimizer-role"
#     Environment = var.environment
#   }
# }

# IAM Policy for cost optimizer Lambda - Temporarily disabled
# resource "aws_iam_role_policy" "cost_optimizer_policy" {
#   count = var.enable_cost_optimization ? 1 : 0
#   
#   name = "${var.project_name}-cost-optimizer-policy"
#   role = aws_iam_role.cost_optimizer_role[0].id
#
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Effect = "Allow"
#         Action = [
#           "logs:CreateLogGroup",
#           "logs:CreateLogStream",
#           "logs:PutLogEvents"
#         ]
#         Resource = "arn:aws:logs:*:*:*"
#       },
#       {
#         Effect = "Allow"
#         Action = [
#           "ec2:DescribeInstances",
#           "ec2:DescribeVolumes",
#           "cloudwatch:GetMetricStatistics",
#           "ce:GetCostAndUsage",
#           "ce:GetUsageReport",
#           "sns:Publish",
#           "tag:GetResources"
#         ]
#         Resource = "*"
#       }
#     ]
#   })
# }

# Create Lambda deployment package for cost optimizer - Temporarily disabled
# data "archive_file" "cost_optimizer_zip" {
#   count = var.enable_cost_optimization ? 1 : 0
#   
#   type        = "zip"
#   output_path = "${path.module}/cost_optimizer_lambda.zip"
#   
#   source {
#     content = templatefile("${path.module}/cost_optimizer_lambda.py", {
#       project_name = var.project_name
#       environment  = var.environment
#     })
#     filename = "cost_optimizer.py"
#   }
# }

# CloudWatch Event Rule for cost optimization - Temporarily disabled
# resource "aws_cloudwatch_event_rule" "cost_optimization_schedule" {
#   count = var.enable_cost_optimization ? 1 : 0
#   
#   name                = "${var.project_name}-cost-optimization-schedule"
#   description         = "Trigger cost optimization Lambda function"
#   schedule_expression = "rate(6 hours)"
#
#   tags = {
#     Name        = "${var.project_name}-cost-optimization-schedule"
#     Environment = var.environment
#   }
# }

# CloudWatch Event Target for cost optimization - Temporarily disabled
# resource "aws_cloudwatch_event_target" "cost_optimization_lambda_target" {
#   count = var.enable_cost_optimization ? 1 : 0
#   
#   rule      = aws_cloudwatch_event_rule.cost_optimization_schedule[0].name
#   target_id = "CostOptimizationLambdaTarget"
#   arn       = aws_lambda_function.cost_optimizer[0].arn
# }

# Lambda permission for CloudWatch Events (cost optimization) - Temporarily disabled
# resource "aws_lambda_permission" "allow_cloudwatch_cost_optimization" {
#   count = var.enable_cost_optimization ? 1 : 0
#   
#   statement_id  = "AllowExecutionFromCloudWatchCostOptimization"
#   action        = "lambda:InvokeFunction"
#   function_name = aws_lambda_function.cost_optimizer[0].function_name
#   principal     = "events.amazonaws.com"
#   source_arn    = aws_cloudwatch_event_rule.cost_optimization_schedule[0].arn
# }


# IAM Role for CloudWatch Agent
resource "aws_iam_role" "cloudwatch_agent" {
  name = "${var.project_name}-cloudwatch-agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-cloudwatch-agent-role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  role       = aws_iam_role.cloudwatch_agent.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "cloudwatch_agent" {
  name = "${var.project_name}-cloudwatch-agent-profile"
  role = aws_iam_role.cloudwatch_agent.name

  tags = {
    Name        = "${var.project_name}-cloudwatch-agent-profile"
    Environment = var.environment
  }
}

# CloudWatch Agent Configuration
resource "aws_ssm_parameter" "cloudwatch_agent_config" {
  name  = "/gameday/${var.project_name}/cloudwatch-agent/config"
  type  = "String"
  value = jsonencode({
    agent = {
      metrics_collection_interval = 60
      run_as_user                 = "root"
    }
    logs = {
      logs_collected = {
        files = {
          collect_list = [
            {
              file_path      = "/var/log/gameday-app.log"
              log_group_name = aws_cloudwatch_log_group.application.name
              log_stream_name = "{instance_id}/application"
              timezone       = "UTC"
            },
            {
              file_path      = "/var/log/messages"
              log_group_name = aws_cloudwatch_log_group.application.name
              log_stream_name = "{instance_id}/system"
              timezone       = "UTC"
            }
          ]
        }
      }
    }
    metrics = {
      namespace = "GameDay/Application"
      metrics_collected = {
        cpu = {
          measurement = [
            "cpu_usage_idle",
            "cpu_usage_iowait",
            "cpu_usage_user",
            "cpu_usage_system"
          ]
          metrics_collection_interval = 60
        }
        disk = {
          measurement = [
            "used_percent"
          ]
          metrics_collection_interval = 60
          resources = [
            "*"
          ]
        }
        mem = {
          measurement = [
            "mem_used_percent"
          ]
          metrics_collection_interval = 60
        }
      }
    }
  })

  tags = {
    Name        = "${var.project_name}-cloudwatch-agent-config"
    Environment = var.environment
  }
}

