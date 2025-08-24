# Security Module - Main Configuration

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.us_east_1]
    }
  }
}

# ALB Security Group - Allow HTTP/HTTPS from internet
resource "aws_security_group" "alb" {
  name_prefix = "${var.project_name}-alb-"
  vpc_id      = var.vpc_id

  # Allow HTTP from internet
  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTPS from internet
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-alb-sg"
    Environment = var.environment
    Purpose     = "ALB Security Group"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# EC2 Application Security Group - Allow HTTP from ALB only
resource "aws_security_group" "app" {
  name_prefix = "${var.project_name}-app-"
  vpc_id      = var.vpc_id

  # Allow HTTP from ALB security group only
  ingress {
    description     = "HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Allow HTTPS from ALB security group only
  ingress {
    description     = "HTTPS from ALB"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Allow SSH from internet (for management)
  ingress {
    description = "SSH from internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow application port from ALB
  ingress {
    description     = "Application port from ALB"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Allow all outbound traffic
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-app-sg"
    Environment = var.environment
    Purpose     = "Application Security Group"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Attack Simulation Security Group - Allow outbound attacks to target application
resource "aws_security_group" "attack_simulation" {
  name_prefix = "${var.project_name}-attack-"
  vpc_id      = var.vpc_id

  # Allow SSH for management
  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr_block]
  }

  # Allow all outbound traffic for attack simulation
  egress {
    description = "All outbound traffic for attacks"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-attack-simulation-sg"
    Environment = var.environment
    Purpose     = "Attack Simulation Security Group"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Database Security Group (for future use with RDS if needed)
resource "aws_security_group" "database" {
  name_prefix = "${var.project_name}-db-"
  vpc_id      = var.vpc_id

  # Allow MySQL/Aurora from application security group
  ingress {
    description     = "MySQL from application"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  # Allow PostgreSQL from application security group
  ingress {
    description     = "PostgreSQL from application"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  tags = {
    Name        = "${var.project_name}-database-sg"
    Environment = var.environment
    Purpose     = "Database Security Group"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Security Level Configuration Mapping
locals {
  security_configs = {
    1 = {
      waf_enabled        = false
      shield_advanced    = false
      cloudfront_enabled = false
      rate_limit         = 10000
      waf_mode          = "COUNT"  # 監視のみ
    }
    2 = {
      waf_enabled        = true
      shield_advanced    = false
      cloudfront_enabled = false
      rate_limit         = 5000
      waf_mode          = "BLOCK"  # ブロック開始
    }
    3 = {
      waf_enabled        = true
      shield_advanced    = false
      cloudfront_enabled = false
      rate_limit         = 2000
      waf_mode          = "BLOCK"
    }
    4 = {
      waf_enabled        = true
      shield_advanced    = false
      cloudfront_enabled = true
      rate_limit         = 1000
      waf_mode          = "BLOCK"
    }
  }
  
  current_config = local.security_configs[var.security_level]
}

# CloudWatch Log Group for WAF
resource "aws_cloudwatch_log_group" "waf_log_group" {
  count             = local.current_config.waf_enabled ? 1 : 0
  name              = "/aws/wafv2/${var.project_name}"
  retention_in_days = 7

  tags = {
    Name        = "${var.project_name}-waf-logs"
    Environment = var.environment
    Purpose     = "WAF Logging"
  }
}

# AWS WAF v2 Web ACL
resource "aws_wafv2_web_acl" "main" {
  count = local.current_config.waf_enabled ? 1 : 0
  name  = "${var.project_name}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # AWS Managed Rules - Common Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rate-based rule for DDoS protection
  rule {
    name     = "RateLimitRule"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = local.current_config.rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name        = "${var.project_name}-waf"
    Environment = var.environment
    Purpose     = "Web Application Firewall"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}WAF"
    sampled_requests_enabled   = true
  }
}

# WAF Logging Configuration (disabled for simplicity)
# resource "aws_wafv2_web_acl_logging_configuration" "main" {
#   count                   = local.current_config.waf_enabled ? 1 : 0
#   resource_arn            = aws_wafv2_web_acl.main[0].arn
#   log_destination_configs = ["${aws_cloudwatch_log_group.waf_log_group[0].arn}:*"]
# }

# CloudFront WAF Web ACL (for CLOUDFRONT scope)
resource "aws_wafv2_web_acl" "cloudfront" {
  count    = local.current_config.cloudfront_enabled ? 1 : 0
  name     = "${var.project_name}-cloudfront-waf"
  scope    = "CLOUDFRONT"
  provider = aws.us_east_1

  default_action {
    allow {}
  }

  # AWS Managed Rules - Common Rule Set for CloudFront
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CloudFrontCommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rate-based rule for CloudFront
  rule {
    name     = "CloudFrontRateLimitRule"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = local.current_config.rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CloudFrontRateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name        = "${var.project_name}-cloudfront-waf"
    Environment = var.environment
    Purpose     = "CloudFront Web Application Firewall"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}CloudFrontWAF"
    sampled_requests_enabled   = true
  }
}

# Origin Access Control for CloudFront - Not needed for ALB origins
# resource "aws_cloudfront_origin_access_control" "main" {
#   count                             = local.current_config.cloudfront_enabled ? 1 : 0
#   name                              = "${var.project_name}-oac"
#   description                       = "Origin Access Control for GameDay ALB"
#   origin_access_control_origin_type = "s3"
#   signing_behavior                  = "always"
#   signing_protocol                  = "sigv4"
# }

# CloudFront Distribution
resource "aws_cloudfront_distribution" "main" {
  count = local.current_config.cloudfront_enabled ? 1 : 0

  origin {
    domain_name              = var.alb_dns_name
    origin_id                = "${var.project_name}-alb-origin"
    # origin_access_control_id = aws_cloudfront_origin_access_control.main[0].id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "CloudFront distribution for GameDay DDoS environment"
  default_root_object = "index.html"

  # Cache behavior for all paths
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${var.project_name}-alb-origin"

    forwarded_values {
      query_string = true
      headers      = ["Host", "User-Agent", "Referer"]

      cookies {
        forward = "all"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
  }

  # Cache behavior for API endpoints (no caching)
  ordered_cache_behavior {
    path_pattern     = "/api/*"
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${var.project_name}-alb-origin"

    forwarded_values {
      query_string = true
      headers      = ["*"]

      cookies {
        forward = "all"
      }
    }

    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Geographic restrictions (none for learning purposes)
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # SSL/TLS certificate configuration
  viewer_certificate {
    cloudfront_default_certificate = true
  }

  # Associate WAF with CloudFront (temporarily disabled for testing)
  # web_acl_id = aws_wafv2_web_acl.cloudfront[0].arn

  # Price class for cost optimization
  price_class = "PriceClass_100"

  tags = {
    Name        = "${var.project_name}-cloudfront"
    Environment = var.environment
    Purpose     = "GameDay-Learning"
  }

  depends_on = [
    aws_wafv2_web_acl.cloudfront
  ]
}

# Shield Advanced Protection - REMOVED for cost optimization
# Shield Standard is included by default for all AWS resources at no additional cost