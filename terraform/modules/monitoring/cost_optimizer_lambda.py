#!/usr/bin/env python3
"""
AWS GameDay Cost Optimization Lambda Function

This function analyzes resource usage and provides cost optimization recommendations.
It monitors EC2 instances, storage usage, and other resources for optimization opportunities.
"""

import json
import boto3
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
import os

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
PROJECT_NAME = os.environ.get("PROJECT_NAME", "aws-gameday-ddos")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "gameday")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")

# AWS clients
ec2 = boto3.client("ec2")
cloudwatch = boto3.client("cloudwatch")
ce = boto3.client("ce")
sns = boto3.client("sns")
resource_groups = boto3.client("resourcegroupstaggingapi")


def lambda_handler(event, context):
    """
    Main Lambda handler function for cost optimization analysis
    """
    try:
        logger.info(f"Starting cost optimization analysis for project: {PROJECT_NAME}")
        
        optimization_results = {
            "recommendations": [],
            "current_costs": {},
            "potential_savings": 0.0,
            "analysis_date": datetime.now(timezone.utc).isoformat()
        }
        
        # Analyze EC2 instances
        ec2_recommendations = analyze_ec2_usage()
        optimization_results['recommendations'].extend(ec2_recommendations)
        
        # Analyze storage usage
        storage_recommendations = analyze_storage_usage()
        optimization_results['recommendations'].extend(storage_recommendations)
        
        # Analyze CloudWatch logs retention
        logs_recommendations = analyze_logs_retention()
        optimization_results['recommendations'].extend(logs_recommendations)
        
        # Get current cost information
        optimization_results['current_costs'] = get_current_costs()
        
        # Calculate potential savings
        optimization_results['potential_savings'] = calculate_potential_savings(
            optimization_results['recommendations']
        )
        
        # Send notification if significant savings are possible
        if optimization_results['potential_savings'] > 5.0:  # $5 threshold
            send_cost_optimization_notification(optimization_results)
        
        logger.info(f"Cost optimization analysis completed. Potential savings: ${optimization_results['potential_savings']:.2f}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Cost optimization analysis completed',
                'results': optimization_results
            })
        }
        
    except Exception as e:
        logger.error(f"Cost optimization analysis failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': f'Cost optimization analysis failed: {str(e)}'
            })
        }


def analyze_ec2_usage() -> List[Dict[str, Any]]:
    """
    Analyze EC2 instance usage and provide optimization recommendations
    """
    recommendations = []
    
    try:
        # Get project EC2 instances
        response = resource_groups.get_resources(
            TagFilters=[
                {
                    'Key': 'Project',
                    'Values': [PROJECT_NAME]
                }
            ],
            ResourceTypeFilters=['ec2:instance']
        )
        
        for resource in response.get('ResourceTagMappingList', []):
            instance_id = resource['ResourceARN'].split('/')[-1]
            
            # Get CPU utilization for the last 7 days
            cpu_utilization = get_cpu_utilization(instance_id)
            
            if cpu_utilization is not None:
                if cpu_utilization < 10.0:  # Low utilization threshold
                    recommendations.append({
                        'type': 'ec2_rightsizing',
                        'resource_id': instance_id,
                        'current_utilization': cpu_utilization,
                        'recommendation': 'Consider downsizing instance or using spot instances',
                        'potential_savings': 15.0,  # Estimated monthly savings
                        'priority': 'high' if cpu_utilization < 5.0 else 'medium'
                    })
                elif cpu_utilization > 80.0:  # High utilization
                    recommendations.append({
                        'type': 'ec2_scaling',
                        'resource_id': instance_id,
                        'current_utilization': cpu_utilization,
                        'recommendation': 'Consider upgrading instance type or adding auto-scaling',
                        'potential_cost_increase': 10.0,
                        'priority': 'medium'
                    })
        
        # Check for unused volumes
        unused_volumes = get_unused_volumes()
        for volume in unused_volumes:
            recommendations.append({
                'type': 'ebs_cleanup',
                'resource_id': volume['VolumeId'],
                'recommendation': 'Delete unused EBS volume',
                'potential_savings': volume['Size'] * 0.10,  # $0.10 per GB per month
                'priority': 'high'
            })
        
    except Exception as e:
        logger.error(f"Error analyzing EC2 usage: {str(e)}")
    
    return recommendations


def analyze_storage_usage() -> List[Dict[str, Any]]:
    """
    Analyze storage usage and provide optimization recommendations
    """
    recommendations = []
    
    try:
        # Get S3 buckets for the project
        response = resource_groups.get_resources(
            TagFilters=[
                {
                    'Key': 'Project',
                    'Values': [PROJECT_NAME]
                }
            ],
            ResourceTypeFilters=['s3:bucket']
        )
        
        for resource in response.get('ResourceTagMappingList', []):
            bucket_name = resource['ResourceARN'].split(':')[-1]
            
            # Analyze bucket usage (simplified)
            recommendations.append({
                'type': 's3_lifecycle',
                'resource_id': bucket_name,
                'recommendation': 'Configure S3 lifecycle policies to transition old objects to cheaper storage classes',
                'potential_savings': 5.0,  # Estimated monthly savings
                'priority': 'low'
            })
    
    except Exception as e:
        logger.error(f"Error analyzing storage usage: {str(e)}")
    
    return recommendations


def analyze_logs_retention() -> List[Dict[str, Any]]:
    """
    Analyze CloudWatch logs retention and provide optimization recommendations
    """
    recommendations = []
    
    try:
        # This is a simplified analysis
        # In practice, you'd check actual log group retention settings
        recommendations.append({
            'type': 'logs_retention',
            'resource_id': 'cloudwatch_logs',
            'recommendation': 'Review log retention periods - consider reducing from 7 days to 3 days for cost savings',
            'potential_savings': 2.0,  # Estimated monthly savings
            'priority': 'low'
        })
    
    except Exception as e:
        logger.error(f"Error analyzing logs retention: {str(e)}")
    
    return recommendations


def get_cpu_utilization(instance_id: str) -> float:
    """
    Get average CPU utilization for an EC2 instance over the last 7 days
    """
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            Dimensions=[
                {
                    'Name': 'InstanceId',
                    'Value': instance_id
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,  # 1 hour
            Statistics=['Average']
        )
        
        if response['Datapoints']:
            avg_cpu = sum(dp['Average'] for dp in response['Datapoints']) / len(response['Datapoints'])
            return round(avg_cpu, 2)
        
        return None
        
    except Exception as e:
        logger.error(f"Error getting CPU utilization for {instance_id}: {str(e)}")
        return None


def get_unused_volumes() -> List[Dict[str, Any]]:
    """
    Get list of unused EBS volumes
    """
    unused_volumes = []
    
    try:
        response = ec2.describe_volumes(
            Filters=[
                {
                    'Name': 'status',
                    'Values': ['available']
                }
            ]
        )
        
        for volume in response['Volumes']:
            # Check if volume has project tag
            project_tag = next((tag['Value'] for tag in volume.get('Tags', []) if tag['Key'] == 'Project'), None)
            if project_tag == PROJECT_NAME:
                unused_volumes.append({
                    'VolumeId': volume['VolumeId'],
                    'Size': volume['Size'],
                    'VolumeType': volume['VolumeType']
                })
    
    except Exception as e:
        logger.error(f"Error getting unused volumes: {str(e)}")
    
    return unused_volumes


def get_current_costs() -> Dict[str, Any]:
    """
    Get current cost information for the project
    """
    try:
        end_date = datetime.now().strftime('%Y-%m-%d')
        start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[
                {
                    'Type': 'DIMENSION',
                    'Key': 'SERVICE'
                }
            ]
        )
        
        costs = {}
        total_cost = 0.0
        
        for result in response.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                costs[service] = cost
                total_cost += cost
        
        return {
            'total_monthly_cost': round(total_cost, 2),
            'cost_by_service': costs,
            'period': f"{start_date} to {end_date}"
        }
        
    except Exception as e:
        logger.error(f"Error getting current costs: {str(e)}")
        return {}


def calculate_potential_savings(recommendations: List[Dict[str, Any]]) -> float:
    """
    Calculate total potential savings from all recommendations
    """
    total_savings = 0.0
    
    for rec in recommendations:
        if 'potential_savings' in rec:
            total_savings += rec['potential_savings']
    
    return round(total_savings, 2)


def send_cost_optimization_notification(results: Dict[str, Any]):
    """
    Send SNS notification about cost optimization recommendations
    """
    try:
        if not SNS_TOPIC_ARN:
            logger.warning("SNS topic ARN not configured, skipping notification")
            return
        
        message = {
            'subject': f'Cost Optimization Report - {PROJECT_NAME}',
            'project': PROJECT_NAME,
            'environment': ENVIRONMENT,
            'analysis_date': results['analysis_date'],
            'potential_monthly_savings': results['potential_savings'],
            'current_monthly_cost': results['current_costs'].get('total_monthly_cost', 'Unknown'),
            'recommendations_count': len(results['recommendations']),
            'top_recommendations': results['recommendations'][:3]  # Top 3 recommendations
        }
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'GameDay Cost Optimization - ${results["potential_savings"]:.2f} Potential Savings',
            Message=json.dumps(message, indent=2)
        )
        
        logger.info(f"Cost optimization notification sent to {SNS_TOPIC_ARN}")
        
    except Exception as e:
        logger.error(f"Error sending cost optimization notification: {str(e)}")