#
# This file is used to define Azure Application Registrations for protecting and providing access to external resources

#    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *
#
# Application Registrations
#
#    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *

# Flask-Azure-OAuth-Provider-Example-App1 (server)
#
# This resource relies on the Azure Active Directory Terraform provider being previously configured
#
# Azure source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added
# Terraform source: https://www.terraform.io/docs/providers/azuread/r/application.html
resource "azuread_application" "example-app1-server" {
  name                       = "Flask Azure OAuth Provider - Example App 1 (Server)"
  type                       = "webapp/api"
  owners                     = ["5db10263-0c44-4707-9aef-e6653542894b", "d7e85202-89d4-4cb9-a5ba-b8b9f01947d8"]
  public_client              = false
  available_to_other_tenants = false
  homepage                   = "https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth"

  # set once the initial application registration has been made and Application ID has been assigned
  identifier_uris = ["api://be76d0cc-26ab-4c07-8bae-ed544224078f"]

  oauth2_allow_implicit_flow = false
  group_membership_claims    = "None"

  app_role {
    allowed_member_types = [
      "User"
    ]
    description  = "Example scope 1."
    display_name = "BAS.WSF.FlaskOAuthProvider.Examples.Example1.Scope1"
    is_enabled   = true
    value        = "BAS.WSF.FlaskOAuthProvider.Examples.Example1.Scope1"
  }
  app_role {
    allowed_member_types = [
      "User"
    ]
    description  = "Example scope 2."
    display_name = "BAS.WSF.FlaskOAuthProvider.Examples.Example1.Scope2"
    is_enabled   = true
    value        = "BAS.WSF.FlaskOAuthProvider.Examples.Example1.Scope2"
  }

  oauth2_permissions {
    admin_consent_description  = "Allow access to Flask OAuth Provider Example App 1."
    admin_consent_display_name = "Flask OAuth Provider Example App 1 Access"
    is_enabled                 = true
    type                       = "Admin"
    value                      = "BAS.WSF.FlaskOAuthProvider.Examples.Example1.Access"
  }
}

# Flask-Azure-OAuth-Provider-Example-App1 (client)
#
# This resource implicitly depends on the 'azuread_application.example-app1-server' resource
# This resource relies on the Azure Active Directory Terraform provider being previously configured
#
# Azure source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added
# Terraform source: https://www.terraform.io/docs/providers/azuread/r/application.html
resource "azuread_application" "example-app1-client" {
  name                       = "Flask Azure OAuth Provider - Example App 1 (Client)"
  type                       = "native"
  owners                     = ["5db10263-0c44-4707-9aef-e6653542894b", "d7e85202-89d4-4cb9-a5ba-b8b9f01947d8"]
  public_client              = true
  available_to_other_tenants = false
  homepage                   = "https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth"

  reply_urls                 = ["https://login.microsoftonline.com/common/oauth2/nativeclient", "http://localhost:9000/auth/callback"]
  oauth2_allow_implicit_flow = false
  group_membership_claims    = "None"
  oauth2_permissions         = []

  required_resource_access {
    resource_app_id = azuread_application.example-app1-server.application_id

    resource_access {
      id   = "56585b1e-22e6-4aba-b22a-ae9e0c01608d"
      type = "Scope"
    }
  }
}

# Flask-Azure-OAuth-Provider-Example-App2 (server)
#
# This resource relies on the Azure Active Directory Terraform provider being previously configured
#
# Azure source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added
# Terraform source: https://www.terraform.io/docs/providers/azuread/r/application.html
resource "azuread_application" "example-app2-server" {
  name                       = "Flask Azure OAuth Provider - Example App 2 (Server)"
  type                       = "webapp/api"
  owners                     = ["5db10263-0c44-4707-9aef-e6653542894b", "d7e85202-89d4-4cb9-a5ba-b8b9f01947d8"]
  public_client              = false
  available_to_other_tenants = false
  homepage                   = "https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth"

  # set once the initial application registration has been made and Application ID has been assigned
  identifier_uris = ["api://de40e653-e63b-46e3-80f6-52a39f055bf3"]

  oauth2_allow_implicit_flow = false
  group_membership_claims    = "None"

  app_role {
    allowed_member_types = [
      "User"
    ]
    description  = "Example scope 1."
    display_name = "BAS.WSF.FlaskOAuthProvider.Examples.Example2.Scope1"
    is_enabled   = true
    value        = "BAS.WSF.FlaskOAuthProvider.Examples.Example2.Scope1"
  }
  app_role {
    allowed_member_types = [
      "User"
    ]
    description  = "Example scope 2."
    display_name = "BAS.WSF.FlaskOAuthProvider.Examples.Example2.Scope2"
    is_enabled   = true
    value        = "BAS.WSF.FlaskOAuthProvider.Examples.Example2.Scope2"
  }

  oauth2_permissions {
    admin_consent_description  = "Allow access to Flask OAuth Provider Example App 2."
    admin_consent_display_name = "Flask OAuth Provider Example App 2 Access"
    is_enabled                 = true
    type                       = "Admin"
    value                      = "BAS.WSF.FlaskOAuthProvider.Examples.Example2.Access"
  }
}

# Flask-Azure-OAuth-Provider-Example-App2 (client)
#
# This resource implicitly depends on the 'azuread_application.example-app2-server' resource
# This resource relies on the Azure Active Directory Terraform provider being previously configured
#
# Azure source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added
# Terraform source: https://www.terraform.io/docs/providers/azuread/r/application.html
resource "azuread_application" "example-app2-client" {
  name                       = "Flask Azure OAuth Provider - Example App 2 (Client)"
  type                       = "native"
  owners                     = ["5db10263-0c44-4707-9aef-e6653542894b", "d7e85202-89d4-4cb9-a5ba-b8b9f01947d8"]
  public_client              = true
  available_to_other_tenants = false
  homepage                   = "https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth"

  reply_urls                 = ["https://login.microsoftonline.com/common/oauth2/nativeclient", "http://localhost:9000/auth/callback"]
  oauth2_allow_implicit_flow = false
  group_membership_claims    = "None"
  oauth2_permissions         = []

  required_resource_access {
    resource_app_id = azuread_application.example-app2-server.application_id

    resource_access {
      id   = "755609ff-1497-4a88-9907-a5050e21a5a5"
      type = "Scope"
    }
  }
}

#    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *
#
# Service Principles (Enterprise applications)
#
#    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *    *

# Flask-Azure-OAuth-Provider-Example-App1 (server)
#
# This resource implicitly depends on the 'azuread_application.example-app1-server' resource
# This resource relies on the Azure Active Directory Terraform provider being previously configured
#
# Azure source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added
# Terraform source: https://www.terraform.io/docs/providers/azuread/r/service_principal.html
resource "azuread_service_principal" "example-app1-server" {
  application_id               = azuread_application.example-app1-server.application_id
  app_role_assignment_required = false
}

# Flask-Azure-OAuth-Provider-Example-App2 (server)
#
# This resource implicitly depends on the 'azuread_application.example-app2-server' resource
# This resource relies on the Azure Active Directory Terraform provider being previously configured
#
# Azure source: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added
# Terraform source: https://www.terraform.io/docs/providers/azuread/r/service_principal.html
resource "azuread_service_principal" "example-app2-server" {
  application_id               = azuread_application.example-app2-server.application_id
  app_role_assignment_required = false
}
