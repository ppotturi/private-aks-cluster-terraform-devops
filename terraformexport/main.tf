resource "azurerm_resource_group" "res-0" {
  location = "uksouth"
  name     = "AATest1RG"
  tags = {
    createdWith = "Terraform"
  }
}
resource "azurerm_container_registry" "res-1" {
  admin_enabled       = true
  location            = "uksouth"
  name                = "AATest1Acr"
  resource_group_name = "AATest1RG"
  sku                 = "Premium"
  identity {
    identity_ids = ["/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/AATest1AcrIdentity"]
    type         = "UserAssigned"
  }
  depends_on = [
    azurerm_user_assigned_identity.res-18,
  ]
}
resource "azurerm_container_registry_scope_map" "res-3" {
  actions                 = ["repositories/*/metadata/read", "repositories/*/metadata/write", "repositories/*/content/read", "repositories/*/content/write", "repositories/*/content/delete"]
  container_registry_name = "AATest1Acr"
  description             = "Can perform all read, write and delete operations on the registry"
  name                    = "_repositories_admin"
  resource_group_name     = "AATest1RG"
  depends_on = [
    azurerm_container_registry.res-1,
  ]
}
resource "azurerm_container_registry_scope_map" "res-4" {
  actions                 = ["repositories/*/content/read"]
  container_registry_name = "AATest1Acr"
  description             = "Can pull any repository of the registry"
  name                    = "_repositories_pull"
  resource_group_name     = "AATest1RG"
  depends_on = [
    azurerm_container_registry.res-1,
  ]
}
resource "azurerm_container_registry_scope_map" "res-5" {
  actions                 = ["repositories/*/content/read", "repositories/*/metadata/read"]
  container_registry_name = "AATest1Acr"
  description             = "Can perform all read operations on the registry"
  name                    = "_repositories_pull_metadata_read"
  resource_group_name     = "AATest1RG"
  depends_on = [
    azurerm_container_registry.res-1,
  ]
}
resource "azurerm_container_registry_scope_map" "res-6" {
  actions                 = ["repositories/*/content/read", "repositories/*/content/write"]
  container_registry_name = "AATest1Acr"
  description             = "Can push to any repository of the registry"
  name                    = "_repositories_push"
  resource_group_name     = "AATest1RG"
  depends_on = [
    azurerm_container_registry.res-1,
  ]
}
resource "azurerm_container_registry_scope_map" "res-7" {
  actions                 = ["repositories/*/metadata/read", "repositories/*/metadata/write", "repositories/*/content/read", "repositories/*/content/write"]
  container_registry_name = "AATest1Acr"
  description             = "Can perform all read and write operations on the registry"
  name                    = "_repositories_push_metadata_write"
  resource_group_name     = "AATest1RG"
  depends_on = [
    azurerm_container_registry.res-1,
  ]
}
resource "azurerm_kubernetes_cluster" "res-8" {
  automatic_channel_upgrade           = "patch"
  dns_prefix                          = "AATest1Aks-dns"
  location                            = "uksouth"
  name                                = "AATest1Aks"
  private_cluster_enabled             = true
  private_cluster_public_fqdn_enabled = true
  resource_group_name                 = "AATest1RG"
  default_node_pool {
    enable_auto_scaling = true
    max_count           = 1
    min_count           = 1
    name                = "agentpool"
    vm_size             = "Standard_DS2_v2"
    vnet_subnet_id      = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet/subnets/PodSubnet"
    upgrade_settings {
      max_surge = "10%"
    }
  }
  identity {
    type = "SystemAssigned"
  }
  maintenance_window_auto_upgrade {
    day_of_week = "Sunday"
    duration    = 4
    frequency   = "Weekly"
    interval    = 1
    start_time  = "00:00"
    utc_offset  = "+00:00"
  }
  maintenance_window_node_os {
    day_of_week = "Sunday"
    duration    = 4
    frequency   = "Weekly"
    interval    = 1
    start_time  = "00:00"
    utc_offset  = "+00:00"
  }
  depends_on = [
    azurerm_subnet.res-42,
  ]
}
resource "azurerm_kubernetes_cluster_node_pool" "res-9" {
  enable_auto_scaling   = true
  kubernetes_cluster_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.ContainerService/managedClusters/AATest1Aks"
  max_count             = 1
  min_count             = 1
  mode                  = "System"
  name                  = "agentpool"
  vm_size               = "Standard_DS2_v2"
  vnet_subnet_id        = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet/subnets/PodSubnet"
  upgrade_settings {
    max_surge = "10%"
  }
  depends_on = [
    azurerm_kubernetes_cluster.res-8,
    azurerm_subnet.res-42,
  ]
}
resource "azurerm_kubernetes_cluster" "res-13" {
  dns_prefix                          = "AATest2Aks-dns"
  location                            = "uksouth"
  name                                = "AATest2Aks"
  private_cluster_enabled             = true
  private_cluster_public_fqdn_enabled = true
  resource_group_name                 = "AATest1RG"
  azure_active_directory_role_based_access_control {
    admin_group_object_ids = ["6e5de8c1-5a4b-409b-994f-0706e4403b77", "78761057-c58c-44b7-aaa7-ce1639c6c4f5"]
    azure_rbac_enabled     = true
    managed                = true
    tenant_id              = "70a908f7-84af-4d86-b0e9-8ada8f5908e3"
  }
  default_node_pool {
    enable_auto_scaling = true
    max_count           = 1
    min_count           = 1
    name                = "agentpool"
    vm_size             = "Standard_DS2_v2"
    vnet_subnet_id      = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet/subnets/SystemSubnet"
    upgrade_settings {
      max_surge = "10%"
    }
  }
  identity {
    identity_ids = ["/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/AATest1AksIdentity"]
    type         = "UserAssigned"
  }
  oms_agent {
    log_analytics_workspace_id      = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
    msi_auth_for_monitoring_enabled = true
  }
  workload_autoscaler_profile {
    keda_enabled                    = true
    vertical_pod_autoscaler_enabled = true
  }
  depends_on = [
    azurerm_user_assigned_identity.res-19,
    azurerm_log_analytics_workspace.res-53,
    # One of azurerm_subnet.res-43,azurerm_subnet_route_table_association.res-44 (can't auto-resolve as their ids are identical)
  ]
}
resource "azurerm_kubernetes_cluster_node_pool" "res-14" {
  enable_auto_scaling   = true
  kubernetes_cluster_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.ContainerService/managedClusters/AATest2Aks"
  max_count             = 1
  min_count             = 1
  mode                  = "System"
  name                  = "agentpool"
  vm_size               = "Standard_DS2_v2"
  vnet_subnet_id        = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet/subnets/SystemSubnet"
  upgrade_settings {
    max_surge = "10%"
  }
  depends_on = [
    azurerm_kubernetes_cluster.res-13,
    # One of azurerm_subnet.res-43,azurerm_subnet_route_table_association.res-44 (can't auto-resolve as their ids are identical)
  ]
}
resource "azurerm_key_vault" "res-16" {
  enable_rbac_authorization       = true
  enabled_for_deployment          = true
  enabled_for_disk_encryption     = true
  enabled_for_template_deployment = true
  location                        = "uksouth"
  name                            = "AATest1AksKeyVault"
  purge_protection_enabled        = true
  resource_group_name             = "AATest1RG"
  sku_name                        = "standard"
  soft_delete_retention_days      = 30
  tags = {
    createdWith = "Terraform"
  }
  tenant_id = "70a908f7-84af-4d86-b0e9-8ada8f5908e3"
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_user_assigned_identity" "res-18" {
  location            = "uksouth"
  name                = "AATest1AcrIdentity"
  resource_group_name = "AATest1RG"
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_user_assigned_identity" "res-19" {
  location            = "uksouth"
  name                = "AATest1AksIdentity"
  resource_group_name = "AATest1RG"
  tags = {
    createdWith = "Terraform"
  }
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_firewall" "res-20" {
  firewall_policy_id  = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/firewallPolicies/AATest1FirewallPolicy"
  location            = "uksouth"
  name                = "AATest1Firewall"
  resource_group_name = "AATest1RG"
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  zones               = ["1", "2", "3"]
  ip_configuration {
    name                 = "fw_ip_config"
    public_ip_address_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/publicIPAddresses/AATest1FirewallPublicIp"
    subnet_id            = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1HubVNet/subnets/AzureFirewallSubnet"
  }
  depends_on = [
    azurerm_firewall_policy.res-21,
    azurerm_public_ip.res-38,
    azurerm_subnet.res-51,
  ]
}
resource "azurerm_firewall_policy" "res-21" {
  location            = "uksouth"
  name                = "AATest1FirewallPolicy"
  resource_group_name = "AATest1RG"
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_firewall_policy_rule_collection_group" "res-22" {
  firewall_policy_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/firewallPolicies/AATest1FirewallPolicy"
  name               = "AksEgressPolicyRuleCollectionGroup"
  priority           = 500
  application_rule_collection {
    action   = "Allow"
    name     = "ApplicationRules"
    priority = 500
    rule {
      destination_fqdns = ["*.cdn.mscr.io", "mcr.microsoft.com", "*.data.mcr.microsoft.com", "management.azure.com", "login.microsoftonline.com", "acs-mirror.azureedge.net", "dc.services.visualstudio.com", "*.opinsights.azure.com", "*.oms.opinsights.azure.com", "*.microsoftonline.com", "*.monitoring.azure.com"]
      name              = "AllowMicrosoftFqdns"
      source_addresses  = ["*"]
      protocols {
        port = 80
        type = "Http"
      }
      protocols {
        port = 443
        type = "Https"
      }
    }
    rule {
      destination_fqdns = ["download.opensuse.org", "security.ubuntu.com", "ntp.ubuntu.com", "packages.microsoft.com", "snapcraft.io"]
      name              = "AllowFqdnsForOsUpdates"
      source_addresses  = ["*"]
      protocols {
        port = 80
        type = "Http"
      }
      protocols {
        port = 443
        type = "Https"
      }
    }
    rule {
      destination_fqdns = ["auth.docker.io", "registry-1.docker.io", "production.cloudflare.docker.com"]
      name              = "AllowImagesFqdns"
      source_addresses  = ["*"]
      protocols {
        port = 80
        type = "Http"
      }
      protocols {
        port = 443
        type = "Https"
      }
    }
    rule {
      destination_fqdns = ["*.bing.com"]
      name              = "AllowBing"
      source_addresses  = ["*"]
      protocols {
        port = 80
        type = "Http"
      }
      protocols {
        port = 443
        type = "Https"
      }
    }
    rule {
      destination_fqdns = ["*.google.com"]
      name              = "AllowGoogle"
      source_addresses  = ["*"]
      protocols {
        port = 80
        type = "Http"
      }
      protocols {
        port = 443
        type = "Https"
      }
    }
  }
  network_rule_collection {
    action   = "Allow"
    name     = "NetworkRules"
    priority = 400
    rule {
      destination_addresses = ["*"]
      destination_ports     = ["123"]
      name                  = "Time"
      protocols             = ["UDP"]
      source_addresses      = ["*"]
    }
    rule {
      destination_addresses = ["*"]
      destination_ports     = ["53"]
      name                  = "DNS"
      protocols             = ["UDP"]
      source_addresses      = ["*"]
    }
    rule {
      destination_addresses = ["AzureContainerRegistry", "MicrosoftContainerRegistry", "AzureActiveDirectory"]
      destination_ports     = ["*"]
      name                  = "ServiceTags"
      protocols             = ["Any"]
      source_addresses      = ["*"]
    }
    rule {
      destination_addresses = ["*"]
      destination_ports     = ["*"]
      name                  = "Internet"
      protocols             = ["TCP"]
      source_addresses      = ["*"]
    }
  }
  depends_on = [
    azurerm_firewall_policy.res-21,
  ]
}
resource "azurerm_private_dns_zone" "res-23" {
  name                = "privatelink.azurecr.io"
  resource_group_name = "AATest1RG"
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_private_dns_zone_virtual_network_link" "res-24" {
  name                  = "link_to_aatest1aksvnet"
  private_dns_zone_name = "privatelink.azurecr.io"
  resource_group_name   = "AATest1RG"
  virtual_network_id    = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet"
  depends_on = [
    azurerm_private_dns_zone.res-23,
    azurerm_virtual_network.res-41,
  ]
}
resource "azurerm_private_dns_zone_virtual_network_link" "res-25" {
  name                  = "link_to_aatest1hubvnet"
  private_dns_zone_name = "privatelink.azurecr.io"
  resource_group_name   = "AATest1RG"
  virtual_network_id    = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1HubVNet"
  depends_on = [
    azurerm_private_dns_zone.res-23,
    azurerm_virtual_network.res-49,
  ]
}
resource "azurerm_private_dns_zone" "res-26" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = "AATest1RG"
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_private_dns_zone_virtual_network_link" "res-27" {
  name                  = "link_to_aatest1aksvnet"
  private_dns_zone_name = "privatelink.blob.core.windows.net"
  resource_group_name   = "AATest1RG"
  virtual_network_id    = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet"
  depends_on = [
    azurerm_private_dns_zone.res-26,
    azurerm_virtual_network.res-41,
  ]
}
resource "azurerm_private_dns_zone_virtual_network_link" "res-28" {
  name                  = "link_to_aatest1hubvnet"
  private_dns_zone_name = "privatelink.blob.core.windows.net"
  resource_group_name   = "AATest1RG"
  virtual_network_id    = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1HubVNet"
  depends_on = [
    azurerm_private_dns_zone.res-26,
    azurerm_virtual_network.res-49,
  ]
}
resource "azurerm_private_dns_zone" "res-29" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = "AATest1RG"
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_private_dns_zone_virtual_network_link" "res-30" {
  name                  = "link_to_aatest1aksvnet"
  private_dns_zone_name = "privatelink.vaultcore.azure.net"
  resource_group_name   = "AATest1RG"
  virtual_network_id    = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet"
  depends_on = [
    azurerm_private_dns_zone.res-29,
    azurerm_virtual_network.res-41,
  ]
}
resource "azurerm_private_dns_zone_virtual_network_link" "res-31" {
  name                  = "link_to_aatest1hubvnet"
  private_dns_zone_name = "privatelink.vaultcore.azure.net"
  resource_group_name   = "AATest1RG"
  virtual_network_id    = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1HubVNet"
  depends_on = [
    azurerm_private_dns_zone.res-29,
    azurerm_virtual_network.res-49,
  ]
}
resource "azurerm_private_endpoint" "res-32" {
  location            = "uksouth"
  name                = "AATest1AcrPrivateEndpoint"
  resource_group_name = "AATest1RG"
  subnet_id           = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet/subnets/VmSubnet"
  tags = {
    createdWith = "Terraform"
  }
  private_dns_zone_group {
    name                 = "AcrPrivateDnsZoneGroup"
    private_dns_zone_ids = ["/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/privateDnsZones/privatelink.azurecr.io"]
  }
  private_service_connection {
    is_manual_connection           = false
    name                           = "AATest1AcrPrivateEndpointConnection"
    private_connection_resource_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.ContainerRegistry/registries/AATest1Acr"
    subresource_names              = ["registry"]
  }
  depends_on = [
    azurerm_container_registry.res-1,
    azurerm_private_dns_zone.res-23,
    azurerm_subnet.res-47,
  ]
}
resource "azurerm_private_endpoint" "res-34" {
  location            = "uksouth"
  name                = "AATest1AksKeyVaultPrivateEndpoint"
  resource_group_name = "AATest1RG"
  subnet_id           = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet/subnets/VmSubnet"
  tags = {
    createdWith = "Terraform"
  }
  private_dns_zone_group {
    name                 = "KeyVaultPrivateDnsZoneGroup"
    private_dns_zone_ids = ["/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"]
  }
  private_service_connection {
    is_manual_connection           = false
    name                           = "AATest1AksKeyVaultPrivateEndpointConnection"
    private_connection_resource_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.KeyVault/vaults/AATest1AksKeyVault"
    subresource_names              = ["vault"]
  }
  depends_on = [
    azurerm_key_vault.res-16,
    azurerm_private_dns_zone.res-29,
    azurerm_subnet.res-47,
  ]
}
resource "azurerm_private_endpoint" "res-36" {
  location            = "uksouth"
  name                = "BootxqyypwupPrivateEndpoint"
  resource_group_name = "AATest1RG"
  subnet_id           = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet/subnets/VmSubnet"
  tags = {
    createdWith = "Terraform"
  }
  private_dns_zone_group {
    name                 = "BlobPrivateDnsZoneGroup"
    private_dns_zone_ids = ["/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"]
  }
  private_service_connection {
    is_manual_connection           = false
    name                           = "BootxqyypwupPrivateEndpointConnection"
    private_connection_resource_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Storage/storageAccounts/bootxqyypwup"
    subresource_names              = ["blob"]
  }
  depends_on = [
    azurerm_private_dns_zone.res-26,
    azurerm_subnet.res-47,
    azurerm_storage_account.res-629,
  ]
}
resource "azurerm_public_ip" "res-38" {
  allocation_method   = "Static"
  location            = "uksouth"
  name                = "AATest1FirewallPublicIp"
  resource_group_name = "AATest1RG"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_route_table" "res-39" {
  location            = "uksouth"
  name                = "DefaultRouteTable"
  resource_group_name = "AATest1RG"
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_route" "res-40" {
  address_prefix         = "0.0.0.0/0"
  name                   = "kubenetfw_fw_r"
  next_hop_in_ip_address = "10.1.0.4"
  next_hop_type          = "VirtualAppliance"
  resource_group_name    = "AATest1RG"
  route_table_name       = "DefaultRouteTable"
  depends_on = [
    azurerm_route_table.res-39,
  ]
}
resource "azurerm_virtual_network" "res-41" {
  address_space       = ["10.0.0.0/16"]
  location            = "uksouth"
  name                = "AATest1AksVNet"
  resource_group_name = "AATest1RG"
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_subnet" "res-42" {
  address_prefixes     = ["10.0.32.0/20"]
  name                 = "PodSubnet"
  resource_group_name  = "AATest1RG"
  virtual_network_name = "AATest1AksVNet"
  depends_on = [
    azurerm_virtual_network.res-41,
  ]
}
resource "azurerm_subnet" "res-43" {
  address_prefixes     = ["10.0.0.0/20"]
  name                 = "SystemSubnet"
  resource_group_name  = "AATest1RG"
  virtual_network_name = "AATest1AksVNet"
  depends_on = [
    azurerm_virtual_network.res-41,
  ]
}
resource "azurerm_subnet_route_table_association" "res-44" {
  route_table_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/routeTables/DefaultRouteTable"
  subnet_id      = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet/subnets/SystemSubnet"
  depends_on = [
    azurerm_route_table.res-39,
    azurerm_subnet.res-43,
  ]
}
resource "azurerm_subnet" "res-45" {
  address_prefixes     = ["10.0.16.0/20"]
  name                 = "UserSubnet"
  resource_group_name  = "AATest1RG"
  virtual_network_name = "AATest1AksVNet"
  depends_on = [
    azurerm_virtual_network.res-41,
  ]
}
resource "azurerm_subnet_route_table_association" "res-46" {
  route_table_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/routeTables/DefaultRouteTable"
  subnet_id      = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet/subnets/UserSubnet"
  depends_on = [
    azurerm_route_table.res-39,
    azurerm_subnet.res-45,
  ]
}
resource "azurerm_subnet" "res-47" {
  address_prefixes     = ["10.0.48.0/20"]
  name                 = "VmSubnet"
  resource_group_name  = "AATest1RG"
  virtual_network_name = "AATest1AksVNet"
  depends_on = [
    azurerm_virtual_network.res-41,
  ]
}
resource "azurerm_virtual_network_peering" "res-48" {
  allow_forwarded_traffic   = true
  name                      = "AATest1AksVNetToAATest1HubVNet"
  remote_virtual_network_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1HubVNet"
  resource_group_name       = "AATest1RG"
  virtual_network_name      = "AATest1AksVNet"
  depends_on = [
    azurerm_virtual_network.res-41,
    azurerm_virtual_network.res-49,
  ]
}
resource "azurerm_virtual_network" "res-49" {
  address_space       = ["10.1.0.0/16"]
  location            = "uksouth"
  name                = "AATest1HubVNet"
  resource_group_name = "AATest1RG"
  tags = {
    createdWith = "Terraform"
  }
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_subnet" "res-50" {
  address_prefixes     = ["10.1.1.0/24"]
  name                 = "AzureBastionSubnet"
  resource_group_name  = "AATest1RG"
  virtual_network_name = "AATest1HubVNet"
  depends_on = [
    azurerm_virtual_network.res-49,
  ]
}
resource "azurerm_subnet" "res-51" {
  address_prefixes     = ["10.1.0.0/24"]
  name                 = "AzureFirewallSubnet"
  resource_group_name  = "AATest1RG"
  virtual_network_name = "AATest1HubVNet"
  depends_on = [
    azurerm_virtual_network.res-49,
  ]
}
resource "azurerm_virtual_network_peering" "res-52" {
  allow_forwarded_traffic   = true
  name                      = "AATest1HubVNetToAATest1AksVNet"
  remote_virtual_network_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.Network/virtualNetworks/AATest1AksVNet"
  resource_group_name       = "AATest1RG"
  virtual_network_name      = "AATest1HubVNet"
  depends_on = [
    azurerm_virtual_network.res-41,
    azurerm_virtual_network.res-49,
  ]
}
resource "azurerm_log_analytics_workspace" "res-53" {
  location            = "uksouth"
  name                = "AATest1AksWorkspace"
  resource_group_name = "AATest1RG"
  tags = {
    module = "log_analytics"
  }
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-54" {
  category                   = "General Exploration"
  display_name               = "All Computers with their most recent data"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_General|AlphabeticallySortedComputers"
  query                      = "search not(ObjectName == \"Advisor Metrics\" or ObjectName == \"ManagedSpace\") | summarize AggregatedValue = max(TimeGenerated) by Computer | limit 500000 | sort by Computer asc\r\n// Oql: NOT(ObjectName=\"Advisor Metrics\" OR ObjectName=ManagedSpace) | measure max(TimeGenerated) by Computer | top 500000 | Sort Computer // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-55" {
  category                   = "General Exploration"
  display_name               = "Stale Computers (data older than 24 hours)"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_General|StaleComputers"
  query                      = "search not(ObjectName == \"Advisor Metrics\" or ObjectName == \"ManagedSpace\") | summarize lastdata = max(TimeGenerated) by Computer | limit 500000 | where lastdata < ago(24h)\r\n// Oql: NOT(ObjectName=\"Advisor Metrics\" OR ObjectName=ManagedSpace) | measure max(TimeGenerated) as lastdata by Computer | top 500000 | where lastdata < NOW-24HOURS // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-56" {
  category                   = "General Exploration"
  display_name               = "Which Management Group is generating the most data points?"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_General|dataPointsPerManagementGroup"
  query                      = "search * | summarize AggregatedValue = count() by ManagementGroupName\r\n// Oql: * | Measure count() by ManagementGroupName // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-57" {
  category                   = "General Exploration"
  display_name               = "Distribution of data Types"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_General|dataTypeDistribution"
  query                      = "search * | extend Type = $table | summarize AggregatedValue = count() by Type\r\n// Oql: * | Measure count() by Type // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-58" {
  category                   = "Log Management"
  display_name               = "All Events"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|AllEvents"
  query                      = "Event | sort by TimeGenerated desc\r\n// Oql: Type=Event // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-59" {
  category                   = "Log Management"
  display_name               = "All Syslogs"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|AllSyslog"
  query                      = "Syslog | sort by TimeGenerated desc\r\n// Oql: Type=Syslog // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-60" {
  category                   = "Log Management"
  display_name               = "All Syslog Records grouped by Facility"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|AllSyslogByFacility"
  query                      = "Syslog | summarize AggregatedValue = count() by Facility\r\n// Oql: Type=Syslog | Measure count() by Facility // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-61" {
  category                   = "Log Management"
  display_name               = "All Syslog Records grouped by ProcessName"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|AllSyslogByProcessName"
  query                      = "Syslog | summarize AggregatedValue = count() by ProcessName\r\n// Oql: Type=Syslog | Measure count() by ProcessName // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-62" {
  category                   = "Log Management"
  display_name               = "All Syslog Records with Errors"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|AllSyslogsWithErrors"
  query                      = "Syslog | where SeverityLevel == \"error\" | sort by TimeGenerated desc\r\n// Oql: Type=Syslog SeverityLevel=error // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-63" {
  category                   = "Log Management"
  display_name               = "Average HTTP Request time by Client IP Address"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|AverageHTTPRequestTimeByClientIPAddress"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = avg(TimeTaken) by cIP\r\n// Oql: Type=W3CIISLog | Measure Avg(TimeTaken) by cIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-64" {
  category                   = "Log Management"
  display_name               = "Average HTTP Request time by HTTP Method"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|AverageHTTPRequestTimeHTTPMethod"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = avg(TimeTaken) by csMethod\r\n// Oql: Type=W3CIISLog | Measure Avg(TimeTaken) by csMethod // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-65" {
  category                   = "Log Management"
  display_name               = "Count of IIS Log Entries by Client IP Address"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|CountIISLogEntriesClientIPAddress"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by cIP\r\n// Oql: Type=W3CIISLog | Measure count() by cIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-66" {
  category                   = "Log Management"
  display_name               = "Count of IIS Log Entries by HTTP Request Method"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|CountIISLogEntriesHTTPRequestMethod"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csMethod\r\n// Oql: Type=W3CIISLog | Measure count() by csMethod // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-67" {
  category                   = "Log Management"
  display_name               = "Count of IIS Log Entries by HTTP User Agent"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|CountIISLogEntriesHTTPUserAgent"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csUserAgent\r\n// Oql: Type=W3CIISLog | Measure count() by csUserAgent // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-68" {
  category                   = "Log Management"
  display_name               = "Count of IIS Log Entries by Host requested by client"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|CountOfIISLogEntriesByHostRequestedByClient"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csHost\r\n// Oql: Type=W3CIISLog | Measure count() by csHost // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-69" {
  category                   = "Log Management"
  display_name               = "Count of IIS Log Entries by URL for the host \"www.contoso.com\" (replace with your own)"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|CountOfIISLogEntriesByURLForHost"
  query                      = "search csHost == \"www.contoso.com\" | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csUriStem\r\n// Oql: Type=W3CIISLog csHost=\"www.contoso.com\" | Measure count() by csUriStem // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-70" {
  category                   = "Log Management"
  display_name               = "Count of IIS Log Entries by URL requested by client (without query strings)"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|CountOfIISLogEntriesByURLRequestedByClient"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csUriStem\r\n// Oql: Type=W3CIISLog | Measure count() by csUriStem // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-71" {
  category                   = "Log Management"
  display_name               = "Count of Events with level \"Warning\" grouped by Event ID"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|CountOfWarningEvents"
  query                      = "Event | where EventLevelName == \"warning\" | summarize AggregatedValue = count() by EventID\r\n// Oql: Type=Event EventLevelName=warning | Measure count() by EventID // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-72" {
  category                   = "Log Management"
  display_name               = "Shows breakdown of response codes"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|DisplayBreakdownRespondCodes"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by scStatus\r\n// Oql: Type=W3CIISLog | Measure count() by scStatus // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-73" {
  category                   = "Log Management"
  display_name               = "Count of Events grouped by Event Log"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|EventsByEventLog"
  query                      = "Event | summarize AggregatedValue = count() by EventLog\r\n// Oql: Type=Event | Measure count() by EventLog // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-74" {
  category                   = "Log Management"
  display_name               = "Count of Events grouped by Event Source"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|EventsByEventSource"
  query                      = "Event | summarize AggregatedValue = count() by Source\r\n// Oql: Type=Event | Measure count() by Source // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-75" {
  category                   = "Log Management"
  display_name               = "Count of Events grouped by Event ID"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|EventsByEventsID"
  query                      = "Event | summarize AggregatedValue = count() by EventID\r\n// Oql: Type=Event | Measure count() by EventID // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-76" {
  category                   = "Log Management"
  display_name               = "Events in the Operations Manager Event Log whose Event ID is in the range between 2000 and 3000"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|EventsInOMBetween2000to3000"
  query                      = "Event | where EventLog == \"Operations Manager\" and EventID >= 2000 and EventID <= 3000 | sort by TimeGenerated desc\r\n// Oql: Type=Event EventLog=\"Operations Manager\" EventID:[2000..3000] // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-77" {
  category                   = "Log Management"
  display_name               = "Count of Events containing the word \"started\" grouped by EventID"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|EventsWithStartedinEventID"
  query                      = "search in (Event) \"started\" | summarize AggregatedValue = count() by EventID\r\n// Oql: Type=Event \"started\" | Measure count() by EventID // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-78" {
  category                   = "Log Management"
  display_name               = "Find the maximum time taken for each page"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|FindMaximumTimeTakenForEachPage"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = max(TimeTaken) by csUriStem\r\n// Oql: Type=W3CIISLog | Measure Max(TimeTaken) by csUriStem // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-79" {
  category                   = "Log Management"
  display_name               = "IIS Log Entries for a specific client IP Address (replace with your own)"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|IISLogEntriesForClientIP"
  query                      = "search cIP == \"192.168.0.1\" | extend Type = $table | where Type == W3CIISLog | sort by TimeGenerated desc | project csUriStem, scBytes, csBytes, TimeTaken, scStatus\r\n// Oql: Type=W3CIISLog cIP=\"192.168.0.1\" | Select csUriStem,scBytes,csBytes,TimeTaken,scStatus // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-80" {
  category                   = "Log Management"
  display_name               = "All IIS Log Entries"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|ListAllIISLogEntries"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | sort by TimeGenerated desc\r\n// Oql: Type=W3CIISLog // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-81" {
  category                   = "Log Management"
  display_name               = "How many connections to Operations Manager's SDK service by day"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|NoOfConnectionsToOMSDKService"
  query                      = "Event | where EventID == 26328 and EventLog == \"Operations Manager\" | summarize AggregatedValue = count() by bin(TimeGenerated, 1d) | sort by TimeGenerated desc\r\n// Oql: Type=Event EventID=26328 EventLog=\"Operations Manager\" | Measure count() interval 1DAY // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-82" {
  category                   = "Log Management"
  display_name               = "When did my servers initiate restart?"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|ServerRestartTime"
  query                      = "search in (Event) \"shutdown\" and EventLog == \"System\" and Source == \"User32\" and EventID == 1074 | sort by TimeGenerated desc | project TimeGenerated, Computer\r\n// Oql: shutdown Type=Event EventLog=System Source=User32 EventID=1074 | Select TimeGenerated,Computer // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-83" {
  category                   = "Log Management"
  display_name               = "Shows which pages people are getting a 404 for"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|Show404PagesList"
  query                      = "search scStatus == 404 | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csUriStem\r\n// Oql: Type=W3CIISLog scStatus=404 | Measure count() by csUriStem // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-84" {
  category                   = "Log Management"
  display_name               = "Shows servers that are throwing internal server error"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|ShowServersThrowingInternalServerError"
  query                      = "search scStatus == 500 | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by sComputerName\r\n// Oql: Type=W3CIISLog scStatus=500 | Measure count() by sComputerName // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-85" {
  category                   = "Log Management"
  display_name               = "Total Bytes received by each Azure Role Instance"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|TotalBytesReceivedByEachAzureRoleInstance"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(csBytes) by RoleInstance\r\n// Oql: Type=W3CIISLog | Measure Sum(csBytes) by RoleInstance // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-86" {
  category                   = "Log Management"
  display_name               = "Total Bytes received by each IIS Computer"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|TotalBytesReceivedByEachIISComputer"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(csBytes) by Computer | limit 500000\r\n// Oql: Type=W3CIISLog | Measure Sum(csBytes) by Computer | top 500000 // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-87" {
  category                   = "Log Management"
  display_name               = "Total Bytes responded back to clients by Client IP Address"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|TotalBytesRespondedToClientsByClientIPAddress"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(scBytes) by cIP\r\n// Oql: Type=W3CIISLog | Measure Sum(scBytes) by cIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-88" {
  category                   = "Log Management"
  display_name               = "Total Bytes responded back to clients by each IIS ServerIP Address"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|TotalBytesRespondedToClientsByEachIISServerIPAddress"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(scBytes) by sIP\r\n// Oql: Type=W3CIISLog | Measure Sum(scBytes) by sIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-89" {
  category                   = "Log Management"
  display_name               = "Total Bytes sent by Client IP Address"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|TotalBytesSentByClientIPAddress"
  query                      = "search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(csBytes) by cIP\r\n// Oql: Type=W3CIISLog | Measure Sum(csBytes) by cIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-90" {
  category                   = "Log Management"
  display_name               = "All Events with level \"Warning\""
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|WarningEvents"
  query                      = "Event | where EventLevelName == \"warning\" | sort by TimeGenerated desc\r\n// Oql: Type=Event EventLevelName=warning // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-91" {
  category                   = "Log Management"
  display_name               = "Windows Firewall Policy settings have changed"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|WindowsFireawallPolicySettingsChanged"
  query                      = "Event | where EventLog == \"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\" and EventID == 2008 | sort by TimeGenerated desc\r\n// Oql: Type=Event EventLog=\"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\" EventID=2008 // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_log_analytics_saved_search" "res-92" {
  category                   = "Log Management"
  display_name               = "On which machines and how many times have Windows Firewall Policy settings changed"
  log_analytics_workspace_id = "/subscriptions/a18dda9b-de63-4ba6-93d5-6e2207dfb92f/resourceGroups/AATest1RG/providers/Microsoft.OperationalInsights/workspaces/AATest1AksWorkspace"
  name                       = "LogManagement(AATest1AksWorkspace)_LogManagement|WindowsFireawallPolicySettingsChangedByMachines"
  query                      = "Event | where EventLog == \"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\" and EventID == 2008 | summarize AggregatedValue = count() by Computer | limit 500000\r\n// Oql: Type=Event EventLog=\"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\" EventID=2008 | measure count() by Computer | top 500000 // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122"
  depends_on = [
    azurerm_log_analytics_workspace.res-53,
  ]
}
resource "azurerm_storage_account" "res-629" {
  account_replication_type = "LRS"
  account_tier             = "Standard"
  location                 = "uksouth"
  name                     = "bootxqyypwup"
  resource_group_name      = "AATest1RG"
  identity {
    type = "SystemAssigned"
  }
  depends_on = [
    azurerm_resource_group.res-0,
  ]
}
resource "azurerm_private_dns_a_record" "res-635" {
  name                = "aatest1acr"
  records             = ["10.0.48.5"]
  resource_group_name = "aatest1rg"
  tags = {
    creator = "created by private endpoint AATest1AcrPrivateEndpoint with resource guid 50845524-3b4d-4eff-95d4-c062a2dfc94e"
  }
  ttl       = 10
  zone_name = "privatelink.azurecr.io"
  depends_on = [
    azurerm_private_dns_zone.res-23,
  ]
}
resource "azurerm_private_dns_a_record" "res-636" {
  name                = "aatest1acr.uksouth.data"
  records             = ["10.0.48.4"]
  resource_group_name = "aatest1rg"
  tags = {
    creator = "created by private endpoint AATest1AcrPrivateEndpoint with resource guid 50845524-3b4d-4eff-95d4-c062a2dfc94e"
  }
  ttl       = 10
  zone_name = "privatelink.azurecr.io"
  depends_on = [
    azurerm_private_dns_zone.res-23,
  ]
}
resource "azurerm_private_dns_a_record" "res-638" {
  name                = "bootxqyypwup"
  records             = ["10.0.48.6"]
  resource_group_name = "aatest1rg"
  tags = {
    creator = "created by private endpoint BootxqyypwupPrivateEndpoint with resource guid cf4934af-c629-44f4-92f5-6e601e91262a"
  }
  ttl       = 10
  zone_name = "privatelink.blob.core.windows.net"
  depends_on = [
    azurerm_private_dns_zone.res-26,
  ]
}
resource "azurerm_private_dns_a_record" "res-640" {
  name                = "aatest1akskeyvault"
  records             = ["10.0.48.7"]
  resource_group_name = "aatest1rg"
  tags = {
    creator = "created by private endpoint AATest1AksKeyVaultPrivateEndpoint with resource guid 853d66d0-6d66-442c-86de-aa6ff7bbbc88"
  }
  ttl       = 10
  zone_name = "privatelink.vaultcore.azure.net"
  depends_on = [
    azurerm_private_dns_zone.res-29,
  ]
}
