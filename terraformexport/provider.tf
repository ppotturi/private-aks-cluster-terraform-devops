provider "azurerm" {
  features {
  }
  use_msi                    = false
  use_cli                    = true
  use_oidc                   = false
  skip_provider_registration = true
  subscription_id            = "a18dda9b-de63-4ba6-93d5-6e2207dfb92f"
  environment                = "public"
}
