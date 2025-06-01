# RuPay UPI Infrastructure

## Overview

This directory contains Terraform code to provision the infrastructure for the RuPay UPI application on AWS. The infrastructure is defined using a modular approach with separate modules for each component.

## Architecture

![Architecture Diagram](./architecture-diagram.png)

The infrastructure includes:

- **VPC and Networking**: Private and public subnets across multiple AZs
- **IAM**: Roles and policies for secure access
- **Database**: Aurora PostgreSQL for data storage
- **Redis**: ElastiCache for caching and OTP storage
- **ECS**: Fargate clusters for running containerized microservices
- **API Gateway**: HTTP API for frontend access
- **Security**: WAF, Shield, and GuardDuty for protection
- **Monitoring**: CloudWatch for logs, metrics, and alarms
- **Storage**: S3 for document storage
- **Messaging**: SQS for asynchronous processing, SNS for notifications, EventBridge for events
- **Secrets**: AWS Secrets Manager for storing credentials

## Modules

- **vpc**: Network infrastructure
- **iam**: Identity and access management
- **database**: Aurora PostgreSQL database
- **redis**: ElastiCache Redis cluster
- **ecs**: ECS cluster and task definitions
- **ecs-service**: Individual ECS services
- **api-gateway**: API Gateway for frontend access
- **security**: WAF, Shield, and GuardDuty
- **monitoring**: CloudWatch logs, metrics, and alarms

## Microservices

- **User Service**: User management and authentication
- **OTP Service**: OTP generation and verification
- **KYC Service**: KYC document upload and verification
- **Payment Service**: Payment processing and settlement
- **Admin Service**: Admin operations and notifications

## Setup Instructions

1. **Install Terraform**:
   Make sure you have Terraform installed (version >= 1.0.0).

2. **Configure AWS Credentials**:
   Set up your AWS credentials using environment variables, AWS CLI configuration, or IAM roles.

3. **Configure Terraform Backend**:
   Edit `backend.tf` to configure the S3 backend for storing Terraform state.

4. **Create terraform.tfvars**:
   Copy `terraform.tfvars.example` to `terraform.tfvars` and fill in the required values.

5. **Initialize Terraform**:

6. **Create a Terraform Workspace**:

7. **Create a Terraform Plan**:

8. **Apply the Terraform Plan**:


## Environment Variables

You can use environment variables to override variables in `terraform.tfvars`:

## Deployment Considerations

- **Staging/Production Deployment**: For production, update the `environment` variable and create a new workspace.
- **Secrets Management**: Sensitive values should be stored in AWS Secrets Manager and not in `terraform.tfvars`.
- **Disaster Recovery**: The infrastructure includes multi-AZ deployment for high availability.
- **Monitoring and Alerting**: CloudWatch alarms are configured to alert on service issues.

## Security Best Practices

1. **Least Privilege**: IAM roles follow least privilege principle.
2. **Network Security**: Private subnets for sensitive resources, security groups restricting access.
3. **Data Encryption**: Data is encrypted at rest and in transit.
4. **WAF Protection**: WAF rules protect against common web exploits.
5. **Secrets Management**: Credentials are stored in AWS Secrets Manager.

## Compliance

This infrastructure is designed to help meet compliance requirements for:

- **PCI-DSS**: For secure payment processing
- **GDPR**: For user data protection
- **Data Localization**: Resources are deployed in the specified region

## Cost Optimization

- Fargate spot instances can be used for non-critical workloads
- Auto-scaling based on demand
- Resource right-sizing based on CloudWatch metrics

## Cleanup

To destroy the infrastructure:

Note: This will delete all resources created by Terraform, including databases. Make sure to backup any important data before running this command.
