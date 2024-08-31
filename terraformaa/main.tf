

terraform {
  required_version = "~> 1.9.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.99.0"
    }
  }
}

provider "azurerm" {
  features {}

  subscription_id = "a18dda9b-de63-4ba6-93d5-6e2207dfb92f"
}

terraform {
  backend "azurerm" {
  }
}

data "azurerm_client_config" "current" {
}

data "azurerm_subscription" "current" {
}

locals {
  resource_group_name = "testDataSourceRg"
}

data "azurerm_resource_group" "externalrg" {
  name = local.resource_group_name
}

output "rg_id" {
  value = data.azurerm_resource_group.externalrg.id
}

output "name" {
  value = data.azurerm_resource_group.externalrg.tags
}