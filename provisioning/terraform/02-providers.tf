#
# This file is used to define Terraform provider resources

# Azure Active Directory provider
#
# The BAS preferred identity management provider
#
# See https://www.terraform.io/docs/providers/azuread/guides/azure_cli.html for how to configure credentials to use
# this provider using the Azure CLI.
#
# AWS source: https://azure.microsoft.com/en-us/services/active-directory/
# Terraform source: https://www.terraform.io/docs/providers/azuread/index.html
provider "azuread" {
  version = "=0.10.0"

  # NERC BAS WebApps Testing
  #
  # Tenancy used as subscription as per [1]
  # [1] https://github.com/terraform-providers/terraform-provider-azuread/issues/259#issuecomment-636387231
  subscription_id = "d14c529b-5558-4a80-93b6-7655681e55d6"
  tenant_id       = "d14c529b-5558-4a80-93b6-7655681e55d6"
}
