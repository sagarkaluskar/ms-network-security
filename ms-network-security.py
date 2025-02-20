
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
import azure.mgmt.network.models as models
from azure.mgmt.network.models import FirewallPolicy
from azure.mgmt.network.models import AzureFirewall


# Azure Subscription ID
subscription_id = "3ec86fc1-67bf-4ab8-9e81-1cd75013ccee"

# Authenticate using Azure credentials
credential = DefaultAzureCredential()
network_client = NetworkManagementClient(credential, subscription_id)

print("Authenticated with Azure successfully!")

#1 Create and Manage Network Security Groups (NSGs)

from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule

# Define NSG name and location
resource_group = "nw-sec-rg"
nsg_name = "MyNSG"
location = "uksouth"

# Create NSG
nsg_params = NetworkSecurityGroup(location=location)
network_client.network_security_groups.begin_create_or_update(resource_group, nsg_name, nsg_params).result()

print(f"NSG '{nsg_name}' created successfully!")

# Define an NSG rule (Allow SSH)
rule_params = SecurityRule(
    protocol="Tcp",
    source_address_prefix="*",
    destination_address_prefix="*",
    access="Allow",
    direction="Inbound",
    source_port_range="*",
    destination_port_range="22",
    priority=100,
    name="AllowSSH"
)

# Add the rule to NSG
network_client.security_rules.begin_create_or_update(resource_group, nsg_name, "AllowSSH", rule_params).result()

print("SSH rule added successfully!")

#2 List Existing NSGs & Rules

nsgs = network_client.network_security_groups.list(resource_group)
for nsg in nsgs:
    print(f"NSG: {nsg.name}, Location: {nsg.location}")

#Get All NSGs. Lists all NSGs in a resource group.

rules = network_client.security_rules.list(resource_group, "MyNSG")
for rule in rules:
    print(f"Rule: {rule.name}, Action: {rule.access}, Port: {rule.destination_port_range}")

#Get NSG Rules. Lists all security rules within MyNSG.

#3 Configure Azure Firewall Rules

# Firewall parameters
firewall_name = "MyFirewall"
firewall_policy_name = "MyFirewallPolicy"
location = "uksouth"

# Create Firewall Policy
firewall_policy = FirewallPolicy(location=location)
network_client.firewall_policies.begin_create_or_update(resource_group, firewall_policy_name, firewall_policy).result()

print("Firewall Policy created successfully!")

# Create Firewall
firewall_params = AzureFirewall(location=location, firewall_policy={'id': f"/subscriptions/3ec86fc1-67bf-4ab8-9e81-1cd75013ccee/resourceGroups/nw-sec-rg/providers/Microsoft.Network/firewallPolicies/MyFirewallPolicy"})
network_client.azure_firewalls.begin_create_or_update(resource_group, firewall_name, firewall_params).result()

print(f"Firewall '{firewall_name}' created successfully!")

#Creates a Firewall Policy.
#Deploys an Azure Firewall in South UK.
#Associates the firewall with the policy.

