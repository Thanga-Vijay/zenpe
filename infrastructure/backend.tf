terraform {
  backend "s3" {
    # Fill these in or pass them as command line arguments
    # bucket         = "your-terraform-state-bucket"
    # key            = "rupay-upi/terraform.tfstate"
    # region         = "ap-south-1"
    # dynamodb_table = "terraform-state-lock"
    # encrypt        = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }

  required_version = ">= 1.0.0"
}
