# Resource Lifecycle Management Module

# Random ID for unique resource naming
resource "random_id" "cleanup_suffix" {
  byte_length = 4
}

# Calculate expiration date (default: 24 hours from creation)
locals {
  expiration_hours = var.resource_expiration_hours
  expiration_date  = timeadd(timestamp(), "${local.expiration_hours}h")
  
  # Common tags for all resources with lifecycle management
  lifecycle_tags = {
    ExpirationDate    = local.expiration_date
    AutoCleanup      = var.auto_cleanup_enabled ? "enabled" : "disabled"
    CreatedBy        = "terraform"
    CreatedAt        = timestamp()
    Project          = var.project_name
    Environment      = var.environment
    CostCenter       = var.cost_center
    Owner            = var.resource_owner
  }
}

# IAM Role for Lambda cleanup function
resource "aws_iam_role" "cleanup_lambda_role" {
  count = var.auto_cleanup_enabled ? 1 : 0
  
  name = "${var.project_name}-cleanup-lambda-role-${random_id.cleanup_suffix.hex}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.lifecycle_tags
}

# IAM Policy for Lambda cleanup function
resource "aws_iam_role_policy" "cleanup_lambda_policy" {
  count = var.auto_cleanup_enabled ? 1 : 0
  
  name = "${var.project_name}-cleanup-lambda-policy"
  role = aws_iam_role.cleanup_lambda_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:TerminateInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeVolumes",
          "ec2:DeleteVolume",
          "ec2:DescribeSnapshots",
          "ec2:DeleteSnapshot",
          "elbv2:DescribeLoadBalancers",
          "elbv2:DeleteLoadBalancer",
          "elbv2:DescribeTargetGroups",
          "elbv2:DeleteTargetGroup",
          "s3:ListBucket",
          "s3:DeleteBucket",
          "s3:DeleteObject",
          "s3:ListBucketVersions",
          "s3:DeleteObjectVersion",
          "cloudwatch:DeleteDashboards",
          "cloudwatch:DeleteAlarms",
          "logs:DeleteLogGroup",
          "wafv2:ListWebACLs",
          "wafv2:DeleteWebACL",
          "cloudfront:ListDistributions",
          "cloudfront:DeleteDistribution",
          "cloudfront:GetDistribution",
          "guardduty:ListDetectors",
          "guardduty:DeleteDetector",
          "tag:GetResources"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda function for automatic resource cleanup
resource "aws_lambda_function" "cleanup_function" {
  count = var.auto_cleanup_enabled ? 1 : 0
  
  filename         = data.archive_file.cleanup_lambda_zip[0].output_path
  function_name    = "${var.project_name}-resource-cleanup-${random_id.cleanup_suffix.hex}"
  role            = aws_iam_role.cleanup_lambda_role[0].arn
  handler         = "cleanup.lambda_handler"
  source_code_hash = data.archive_file.cleanup_lambda_zip[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 300

  environment {
    variables = {
      PROJECT_NAME = var.project_name
      ENVIRONMENT  = var.environment
      DRY_RUN      = var.cleanup_dry_run ? "true" : "false"
    }
  }

  tags = local.lifecycle_tags
}

# Create Lambda deployment package
data "archive_file" "cleanup_lambda_zip" {
  count = var.auto_cleanup_enabled ? 1 : 0
  
  type        = "zip"
  output_path = "${path.module}/cleanup_lambda.zip"
  
  source {
    content = templatefile("${path.module}/cleanup_lambda.py", {
      project_name = var.project_name
      environment  = var.environment
    })
    filename = "cleanup.py"
  }
}

# CloudWatch Event Rule for scheduled cleanup
resource "aws_cloudwatch_event_rule" "cleanup_schedule" {
  count = var.auto_cleanup_enabled ? 1 : 0
  
  name                = "${var.project_name}-cleanup-schedule"
  description         = "Trigger resource cleanup Lambda function"
  schedule_expression = var.cleanup_schedule_expression

  tags = local.lifecycle_tags
}

# CloudWatch Event Target
resource "aws_cloudwatch_event_target" "cleanup_lambda_target" {
  count = var.auto_cleanup_enabled ? 1 : 0
  
  rule      = aws_cloudwatch_event_rule.cleanup_schedule[0].name
  target_id = "CleanupLambdaTarget"
  arn       = aws_lambda_function.cleanup_function[0].arn
}

# Lambda permission for CloudWatch Events
resource "aws_lambda_permission" "allow_cloudwatch" {
  count = var.auto_cleanup_enabled ? 1 : 0
  
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cleanup_function[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cleanup_schedule[0].arn
}

# CloudWatch Log Group for Lambda function
resource "aws_cloudwatch_log_group" "cleanup_lambda_logs" {
  count = var.auto_cleanup_enabled ? 1 : 0
  
  name              = "/aws/lambda/${aws_lambda_function.cleanup_function[0].function_name}"
  retention_in_days = var.log_retention_days

  tags = local.lifecycle_tags
}

# SNS Topic for cleanup notifications
resource "aws_sns_topic" "cleanup_notifications" {
  count = var.enable_cleanup_notifications ? 1 : 0
  
  name = "${var.project_name}-cleanup-notifications"

  tags = local.lifecycle_tags
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "cleanup_notifications_policy" {
  count = var.enable_cleanup_notifications ? 1 : 0
  
  arn = aws_sns_topic.cleanup_notifications[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sns:Publish"
        Resource = aws_sns_topic.cleanup_notifications[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}