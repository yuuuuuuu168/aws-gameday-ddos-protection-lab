# Compute Module - Outputs

output "vulnerable_app_instance_id" {
  description = "ID of the vulnerable web application EC2 instance"
  value       = aws_instance.vulnerable_app.id
}

output "vulnerable_app_private_ip" {
  description = "Private IP of the vulnerable web application instance"
  value       = aws_instance.vulnerable_app.private_ip
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for application logs"
  value       = aws_cloudwatch_log_group.app_logs.name
}

output "ec2_iam_role_arn" {
  description = "ARN of the IAM role for EC2 instances"
  value       = aws_iam_role.ec2_cloudwatch_role.arn
}

# ALB outputs
output "application_url" {
  description = "URL of the vulnerable web application"
  value       = "http://${aws_lb.main.dns_name}"
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.main.arn
}

output "alb_arn_suffix" {
  description = "ARN suffix of the Application Load Balancer"
  value       = aws_lb.main.arn_suffix
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.main.zone_id
}

output "target_group_arn" {
  description = "ARN of the target group"
  value       = aws_lb_target_group.app.arn
}

output "alb_logs_bucket_name" {
  description = "Name of the S3 bucket for ALB access logs"
  value       = aws_s3_bucket.alb_logs.id
}

# Placeholder for attack simulation instance (will be implemented in task 7.3)
output "attack_instance_ip" {
  description = "Public IP of the attack simulation instance"
  value       = "" # Will be implemented in task 7.3
}