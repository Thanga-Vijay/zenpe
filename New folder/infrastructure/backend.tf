terraform {
  backend "s3" {
    bucket = "zenpe-tf-bucket"
    key    = "dev/terraform.tfstate"
    region = "ap-south-1"
    encrypt = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }

  required_version = ">= 1.0.0"
}
