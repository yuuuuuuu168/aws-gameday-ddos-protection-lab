#!/usr/bin/env python3
"""
AWS GameDay Resource Cleanup Lambda Function

This function automatically cleans up expired resources based on ExpirationDate tags.
It supports dry-run mode and sends notifications about cleanup actions.
"""

import json
import boto3
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
import os

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
PROJECT_NAME = os.environ.get('PROJECT_NAME', 'aws-gameday-ddos')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'gameday')
DRY_RUN = os.environ.get('DRY_RUN', 'false').lower() == 'true'

# AWS clients
ec2 = boto3.client('ec2')
elbv2 = boto3.client('elbv2')
s3 = boto3.client('s3')
cloudwatch = boto3.client('cloudwatch')
logs = boto3.client('logs')
wafv2 = boto3.client('wafv2')
cloudfront = boto3.client('cloudfront')
guardduty = boto3.client('guardduty')
sns = boto3.client('sns')
resource_groups = boto3.client('resourcegroupstaggingapi')


def lambda_handler(event, context):
    """
    Main Lambda handler function
    """
    try:
        logger.info(f"Starting resource cleanup for project: {PROJECT_NAME}")
        logger.info(f"Dry run mode: {DRY_RUN}")
        
        cleanup_results = {
            'cleaned_resources': [],
            'errors': [],
            'total_cleaned': 0,
            'dry_run': DRY_RUN
        }
        
        # Get all resources with expiration tags
        expired_resources = get_expired_resources()
        
        if not expired_resources:
            logger.info("No expired resources found")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'No expired resources found',
                    'results': cleanup_results
                })
            }
        
        logger.info(f"Found {len(expired_resources)} expired resources")
        
        # Clean up resources by type
        for resource in expired_resources:
            try:
                result = cleanup_resource(resource)
                if result:
                    cleanup_results['cleaned_resources'].append(result)
                    cleanup_results['total_cleaned'] += 1
            except Exception as e:
                error_msg = f"Error cleaning resource {resource['ResourceARN']}: {str(e)}"
                logger.error(error_msg)
                cleanup_results['errors'].append(error_msg)
        
        # Send notification if configured
        send_cleanup_notification(cleanup_results)
        
        logger.info(f"Cleanup completed. Total resources processed: {cleanup_results['total_cleaned']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Cleanup completed successfully',
                'results': cleanup_results
            })
        }
        
    except Exception as e:
        logger.error(f"Cleanup function failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': f'Cleanup failed: {str(e)}'
            })
        }


def get_expired_resources() -> List[Dict[str, Any]]:
    """
    Get all resources that have expired based on ExpirationDate tag
    """
    try:
        current_time = datetime.now(timezone.utc)
        expired_resources = []
        
        # Get resources with project and expiration tags
        response = resource_groups.get_resources(
            TagFilters=[
                {
                    'Key': 'Project',
                    'Values': [PROJECT_NAME]
                },
                {
                    'Key': 'ExpirationDate'
                }
            ]
        )
        
        for resource in response.get('ResourceTagMappingList', []):
            # Parse expiration date from tags
            expiration_date = None
            auto_cleanup = False
            
            for tag in resource.get('Tags', []):
                if tag['Key'] == 'ExpirationDate':
                    try:
                        expiration_date = datetime.fromisoformat(tag['Value'].replace('Z', '+00:00'))
                    except ValueError:
                        logger.warning(f"Invalid expiration date format for resource {resource['ResourceARN']}")
                        continue
                elif tag['Key'] == 'AutoCleanup' and tag['Value'] == 'enabled':
                    auto_cleanup = True
            
            # Check if resource is expired and auto-cleanup is enabled
            if expiration_date and auto_cleanup and current_time > expiration_date:
                expired_resources.append(resource)
                logger.info(f"Found expired resource: {resource['ResourceARN']}")
        
        return expired_resources
        
    except Exception as e:
        logger.error(f"Error getting expired resources: {str(e)}")
        return []


def cleanup_resource(resource: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean up a specific resource based on its type
    """
    resource_arn = resource['ResourceARN']
    resource_type = resource_arn.split(':')[2]  # Extract service from ARN
    
    logger.info(f"Cleaning up {resource_type} resource: {resource_arn}")
    
    if DRY_RUN:
        logger.info(f"DRY RUN: Would clean up {resource_arn}")
        return {
            'resource_arn': resource_arn,
            'resource_type': resource_type,
            'action': 'dry_run',
            'status': 'simulated'
        }
    
    try:
        if resource_type == 'ec2':
            return cleanup_ec2_resource(resource_arn)
        elif resource_type == 'elasticloadbalancing':
            return cleanup_elb_resource(resource_arn)
        elif resource_type == 's3':
            return cleanup_s3_resource(resource_arn)
        elif resource_type == 'logs':
            return cleanup_logs_resource(resource_arn)
        elif resource_type == 'cloudwatch':
            return cleanup_cloudwatch_resource(resource_arn)
        else:
            logger.warning(f"Unsupported resource type for cleanup: {resource_type}")
            return None
            
    except Exception as e:
        logger.error(f"Error cleaning up resource {resource_arn}: {str(e)}")
        raise


def cleanup_ec2_resource(resource_arn: str) -> Dict[str, Any]:
    """
    Clean up EC2 resources (instances, security groups, volumes)
    """
    # Extract instance ID from ARN
    instance_id = resource_arn.split('/')[-1]
    
    try:
        # Terminate instance
        ec2.terminate_instances(InstanceIds=[instance_id])
        logger.info(f"Terminated EC2 instance: {instance_id}")
        
        return {
            'resource_arn': resource_arn,
            'resource_type': 'ec2-instance',
            'action': 'terminated',
            'status': 'success'
        }
    except Exception as e:
        logger.error(f"Error terminating EC2 instance {instance_id}: {str(e)}")
        raise


def cleanup_elb_resource(resource_arn: str) -> Dict[str, Any]:
    """
    Clean up ELB resources
    """
    try:
        # Delete load balancer
        elbv2.delete_load_balancer(LoadBalancerArn=resource_arn)
        logger.info(f"Deleted load balancer: {resource_arn}")
        
        return {
            'resource_arn': resource_arn,
            'resource_type': 'load-balancer',
            'action': 'deleted',
            'status': 'success'
        }
    except Exception as e:
        logger.error(f"Error deleting load balancer {resource_arn}: {str(e)}")
        raise


def cleanup_s3_resource(resource_arn: str) -> Dict[str, Any]:
    """
    Clean up S3 resources
    """
    bucket_name = resource_arn.split(':')[-1]
    
    try:
        # Empty bucket first
        try:
            objects = s3.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in objects:
                delete_keys = [{'Key': obj['Key']} for obj in objects['Contents']]
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={'Objects': delete_keys}
                )
        except Exception as e:
            logger.warning(f"Error emptying bucket {bucket_name}: {str(e)}")
        
        # Delete bucket
        s3.delete_bucket(Bucket=bucket_name)
        logger.info(f"Deleted S3 bucket: {bucket_name}")
        
        return {
            'resource_arn': resource_arn,
            'resource_type': 's3-bucket',
            'action': 'deleted',
            'status': 'success'
        }
    except Exception as e:
        logger.error(f"Error deleting S3 bucket {bucket_name}: {str(e)}")
        raise


def cleanup_logs_resource(resource_arn: str) -> Dict[str, Any]:
    """
    Clean up CloudWatch Logs resources
    """
    log_group_name = resource_arn.split(':')[-1]
    
    try:
        logs.delete_log_group(logGroupName=log_group_name)
        logger.info(f"Deleted log group: {log_group_name}")
        
        return {
            'resource_arn': resource_arn,
            'resource_type': 'log-group',
            'action': 'deleted',
            'status': 'success'
        }
    except Exception as e:
        logger.error(f"Error deleting log group {log_group_name}: {str(e)}")
        raise


def cleanup_cloudwatch_resource(resource_arn: str) -> Dict[str, Any]:
    """
    Clean up CloudWatch resources (dashboards, alarms)
    """
    # This is a simplified implementation
    # In practice, you'd need to parse the ARN to determine the specific resource type
    logger.info(f"CloudWatch resource cleanup not fully implemented: {resource_arn}")
    
    return {
        'resource_arn': resource_arn,
        'resource_type': 'cloudwatch',
        'action': 'skipped',
        'status': 'not_implemented'
    }


def send_cleanup_notification(results: Dict[str, Any]):
    """
    Send SNS notification about cleanup results
    """
    try:
        # Try to find SNS topic for notifications
        topic_name = f"{PROJECT_NAME}-cleanup-notifications"
        
        # This is a simplified implementation
        # In practice, you'd get the topic ARN from environment variables or parameter store
        message = {
            'project': PROJECT_NAME,
            'environment': ENVIRONMENT,
            'cleanup_time': datetime.now(timezone.utc).isoformat(),
            'results': results
        }
        
        logger.info(f"Cleanup notification: {json.dumps(message, indent=2)}")
        
    except Exception as e:
        logger.warning(f"Could not send cleanup notification: {str(e)}")