# Compute Module - Main Configuration
# EC2 instances and Application Load Balancer for GameDay DDoS Environment

# Data sources for AMI selection
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# CloudWatch Log Groups for application logging
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/aws/ec2/gameday-app"
  retention_in_days = 7

  tags = {
    Name        = "${var.project_name}-app-logs"
    Environment = var.environment
  }
}

# IAM Role for EC2 instance (CloudWatch logging)
resource "aws_iam_role" "ec2_cloudwatch_role" {
  name = "${var.project_name}-ec2-cloudwatch-role"

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
    Name        = "${var.project_name}-ec2-cloudwatch-role"
    Environment = var.environment
  }
}

# IAM Policy for CloudWatch Logs
resource "aws_iam_role_policy" "ec2_cloudwatch_policy" {
  name = "${var.project_name}-ec2-cloudwatch-policy"
  role = aws_iam_role.ec2_cloudwatch_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = [
          aws_cloudwatch_log_group.app_logs.arn,
          "${aws_cloudwatch_log_group.app_logs.arn}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeVolumes",
          "ec2:DescribeTags",
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.ec2_cloudwatch_role.name

  tags = {
    Name        = "${var.project_name}-ec2-profile"
    Environment = var.environment
  }
}

# User data script for application installation
locals {
  user_data = base64encode(file("${path.module}/user_data.sh"))
}

# Data source for current AWS region
data "aws_region" "current" {}

# EC2 Instance for Vulnerable Web Application
resource "aws_instance" "vulnerable_app" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.instance_type
  subnet_id                   = var.public_subnet_ids[0]
  vpc_security_group_ids      = [var.app_security_group_id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = true

  user_data = local.user_data

  # Enable detailed monitoring for better observability
  monitoring = true

  # Root volume configuration
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    delete_on_termination = true
    encrypted             = true

    tags = {
      Name        = "${var.project_name}-app-root-volume"
      Environment = var.environment
    }
  }

  # Metadata service configuration (IMDSv2 required for security)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  tags = {
    Name        = "${var.project_name}-vulnerable-app"
    Environment = var.environment
    Purpose     = "GameDay-Learning"
    Application = "Vulnerable-Web-App"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_security_group_id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = false

  # Access logging to S3 (optional for cost optimization)
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb-access-logs"
    enabled = true
  }

  tags = {
    Name        = "${var.project_name}-alb"
    Environment = var.environment
    Purpose     = "GameDay-Learning"
  }
}

# S3 bucket for ALB access logs
resource "aws_s3_bucket" "alb_logs" {
  bucket        = "${var.project_name}-alb-logs-${random_string.bucket_suffix.result}"
  force_destroy = true

  tags = {
    Name        = "${var.project_name}-alb-logs"
    Environment = var.environment
    Purpose     = "ALB-Access-Logs"
  }
}

# Random string for unique bucket naming
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# S3 bucket versioning
resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 bucket server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 bucket public access block
resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket lifecycle configuration for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "delete_old_logs"
    status = "Enabled"

    filter {
      prefix = "alb-access-logs/"
    }

    expiration {
      days = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }
}

# Data source for ALB service account (for S3 bucket policy)
data "aws_elb_service_account" "main" {}

# S3 bucket policy for ALB access logs
resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_elb_service_account.main.arn
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/alb-access-logs/AWSLogs/*"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/alb-access-logs/AWSLogs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_elb_service_account.main.arn
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs.arn
      }
    ]
  })
}

# Target Group for the vulnerable web application
resource "aws_lb_target_group" "app" {
  name     = "${var.project_name}-app-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  # Health check configuration
  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/"
    matcher             = "200"
    port                = "traffic-port"
    protocol            = "HTTP"
  }

  # Stickiness configuration (disabled for learning purposes)
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 86400
    enabled         = false
  }

  tags = {
    Name        = "${var.project_name}-app-target-group"
    Environment = var.environment
    Purpose     = "GameDay-Learning"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Target Group Attachment
resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.vulnerable_app.id
  port             = 3000
}

# ALB Listener for HTTP traffic
resource "aws_lb_listener" "app_http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }

  tags = {
    Name        = "${var.project_name}-http-listener"
    Environment = var.environment
  }
}

# ALB Listener Rule for application routing
resource "aws_lb_listener_rule" "app_routing" {
  listener_arn = aws_lb_listener.app_http.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }

  condition {
    path_pattern {
      values = ["/*"]
    }
  }

  tags = {
    Name        = "${var.project_name}-app-routing-rule"
    Environment = var.environment
  }
}

# WAF Association with ALB (conditional based on security level)
resource "aws_wafv2_web_acl_association" "alb" {
  count        = var.waf_web_acl_arn != null ? 1 : 0
  resource_arn = aws_lb.main.arn
  web_acl_arn  = var.waf_web_acl_arn

  depends_on = [
    aws_lb.main
  ]
}