# AWS GameDay DDoS Environment - Main Configuration

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }

  # Backend configuration for state management
  backend "s3" {
    # These values should be provided via backend config file or CLI
    # bucket = "your-terraform-state-bucket"
    # key    = "gameday-ddos/terraform.tfstate"
    # region = "us-east-1"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AWS-GameDay-DDoS"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# AWS Provider for us-east-1 (required for CloudFront WAF)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "AWS-GameDay-DDoS"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# Module declarations
module "network" {
  source = "./modules/network"

  vpc_cidr           = var.vpc_cidr
  availability_zones = data.aws_availability_zones.available.names
  environment        = var.environment
  project_name       = var.project_name
}

module "security" {
  source = "./modules/security"

  vpc_id             = module.network.vpc_id
  vpc_cidr_block     = var.vpc_cidr
  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids
  alb_dns_name       = module.compute.alb_dns_name
  alb_arn            = module.compute.alb_arn
  security_level     = var.security_level
  environment        = var.environment
  project_name       = var.project_name

  providers = {
    aws.us_east_1 = aws.us_east_1
  }
}

module "compute" {
  source = "./modules/compute"

  vpc_id                   = module.network.vpc_id
  public_subnet_ids        = module.network.public_subnet_ids
  private_subnet_ids       = module.network.private_subnet_ids
  app_security_group_id    = module.security.app_security_group_id
  alb_security_group_id    = module.security.alb_security_group_id
  attack_security_group_id = module.security.attack_security_group_id
  waf_web_acl_arn          = module.security.waf_web_acl_arn
  environment              = var.environment
  project_name             = var.project_name
  instance_type            = var.instance_type
}

module "monitoring" {
  source = "./modules/monitoring"

  vpc_id                      = module.network.vpc_id
  alb_arn_suffix              = module.compute.alb_arn_suffix
  waf_web_acl_name            = module.security.waf_web_acl_name
  environment                 = var.environment
  project_name                = var.project_name
  security_level              = var.security_level
  budget_limit_usd            = var.budget_limit
  budget_notification_emails  = var.budget_notification_emails
  cost_anomaly_threshold_usd  = var.cost_anomaly_threshold_usd
  daily_cost_threshold_usd    = var.daily_cost_threshold_usd
  enable_cost_optimization    = var.enable_cost_optimization
}

module "attack_simulation" {
  source = "./modules/attack_simulation"

  vpc_id                     = module.network.vpc_id
  subnet_id                  = module.network.public_subnet_ids[0]
  target_alb_dns             = module.compute.alb_dns_name
  target_cloudfront_domain   = module.security.cloudfront_domain_name
  aws_region                 = var.aws_region
  environment                = var.environment
  project_name               = var.project_name
  instance_type              = var.attack_instance_type
  key_pair_name              = var.key_pair_name
  enable_attack_simulation   = var.enable_attack_simulation
  create_results_bucket      = var.create_attack_results_bucket
  allowed_ssh_cidr_blocks    = var.allowed_ssh_cidr_blocks
}

module "resource_management" {
  source = "./modules/resource_management"

  project_name                  = var.project_name
  environment                   = var.environment
  auto_cleanup_enabled          = var.auto_cleanup_enabled
  resource_expiration_hours     = var.resource_expiration_hours
  cleanup_schedule_expression   = var.cleanup_schedule_expression
  cleanup_dry_run              = var.cleanup_dry_run
  log_retention_days           = var.log_retention_days
  enable_cleanup_notifications = var.enable_cleanup_notifications
  cost_center                  = var.cost_center
  resource_owner               = var.resource_owner
  cleanup_notification_email   = var.cleanup_notification_email
}
