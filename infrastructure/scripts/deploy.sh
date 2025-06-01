#!/bin/bash
set -e

# Default values
ENVIRONMENT="dev"
WORKSPACE="dev"
ACTION="plan"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --environment|-e)
      ENVIRONMENT="$2"
      WORKSPACE="$2"
      shift
      shift
      ;;
    --workspace|-w)
      WORKSPACE="$2"
      shift
      shift
      ;;
    --action|-a)
      ACTION="$2"
      shift
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--environment|-e dev|staging|prod] [--workspace|-w workspace_name] [--action|-a plan|apply|destroy]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--environment|-e dev|staging|prod] [--workspace|-w workspace_name] [--action|-a plan|apply|destroy]"
      exit 1
      ;;
  esac
done

echo "Deploying to environment: $ENVIRONMENT, using workspace: $WORKSPACE, action: $ACTION"

# Check if Terraform is installed
if ! command -v terraform &> /dev/null; then
    echo "Terraform could not be found. Please install Terraform."
    exit 1
fi

# Initialize Terraform
echo "Initializing Terraform..."
terraform init

# Check if workspace exists, create if it doesn't
WORKSPACE_EXISTS=$(terraform workspace list | grep -c "$WORKSPACE" || true)
if [ "$WORKSPACE_EXISTS" -eq 0 ]; then
    echo "Creating workspace: $WORKSPACE"
    terraform workspace new "$WORKSPACE"
else
    echo "Selecting workspace: $WORKSPACE"
    terraform workspace select "$WORKSPACE"
fi

# Execute the specified action
case $ACTION in
  plan)
    echo "Creating Terraform plan..."
    terraform plan -var="environment=$ENVIRONMENT" -out=tfplan
    ;;
  apply)
    echo "Applying Terraform plan..."
    terraform apply -var="environment=$ENVIRONMENT" -auto-approve
    ;;
  destroy)
    echo "Destroying Terraform resources..."
    terraform destroy -var="environment=$ENVIRONMENT" -auto-approve
    ;;
  *)
    echo "Unknown action: $ACTION"
    echo "Supported actions: plan, apply, destroy"
    exit 1
    ;;
esac

echo "Deployment completed successfully!"
