
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
import azure.mgmt.network.models as models
from azure.mgmt.network.models import FirewallPolicy
from azure.mgmt.network.models import AzureFirewall
from azure.mgmt.network.models import ApplicationGateway, ApplicationGatewayWebApplicationFirewallConfiguration
from azure.mgmt.network.models import VirtualNetwork, Subnet
from azure.mgmt.network import NetworkManagementClient
import time
from azure.mgmt.network.models import FirewallPolicy
from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient

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

# Set up credentials using DefaultAzureCredential (this will use your Azure CLI or environment credentials)
credential = DefaultAzureCredential()

subscription_id = "3ec86fc1-67bf-4ab8-9e81-1cd75013ccee"
resource_group = "nw-sec-rg"

# Initialize the network client
network_client = NetworkManagementClient(credential, subscription_id)

# Function to wait for the firewall policy operation to complete
def wait_for_operation_to_complete(resource_group, firewall_policy_name, operation_id):
    while True:
        try:
            # Fetch the firewall policy status
            firewall_policy = network_client.firewall_policies.get(resource_group, firewall_policy_name)
            if firewall_policy.provisioning_state == 'Succeeded':
                print(f"Firewall Policy '{firewall_policy_name}' updated successfully!")
                return
            elif firewall_policy.provisioning_state == 'Failed':
                print(f"Firewall Policy '{firewall_policy_name}' update failed.")
                return
            else:
                print(f"Operation in progress... Current status: {firewall_policy.provisioning_state}")
        except HttpResponseError as e:
            print(f"Error fetching policy status: {str(e)}")
        
        time.sleep(10)  # Wait 10 seconds before polling again

# Assuming you have an operation ID from the error message
operation_id = "9359aca4-1c0c-48dd-b949-32ae057d5560"

# Poll for operation completion
wait_for_operation_to_complete(resource_group, "MyFirewallPolicy", operation_id)

# Once the operation is complete, you can proceed with further updates

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

#4 Create an Application Gateway and Configure Web Application Firewall (WAF)

# Parameters
resource_group = 'nw-sec-rg'
vnet_name = 'myVNet'
location = 'uksouth'

# Create Virtual Network
vnet_params = VirtualNetwork(
    location=location,
    address_space={'address_prefixes': ['10.0.0.0/16']},
    subnets=[Subnet(name='mySubnet', address_prefix='10.0.0.0/24')]
)
vnet = network_client.virtual_networks.begin_create_or_update(
    resource_group, vnet_name, vnet_params).result()

print(f"Virtual Network '{vnet_name}' created successfully!")

# Parameters
resource_group = 'nw-sec-rg'
gateway_name = 'MyAppGateway'
location = 'uksouth'
vnet_name = 'myVNet'
subnet_name = 'mySubnet'

# WAF Configuration
waf_config = ApplicationGatewayWebApplicationFirewallConfiguration(
    enabled=True,
    firewall_mode="Prevention",
    rule_set_type="OWASP",
    rule_set_version="3.1"
)

# Reference the subnet within the virtual network
subnet_id = f"/subscriptions/3ec86fc1-67bf-4ab8-9e81-1cd75013ccee/resourceGroups/nw-sec-rg/providers/Microsoft.Network/virtualNetworks/myVNet/subnets/mySubnet"

# Create Application Gateway with WAF enabled
app_gateway_params = ApplicationGateway(
    location=location,
    sku={'name': 'Standard_V2', 'tier': 'Standard_V2'},
    gateway_ip_configurations=[{
        'name': 'gw_ip_config',
        'subnet': {'id': f'/subscriptions/3ec86fc1-67bf-4ab8-9e81-1cd75013ccee/resourceGroups/nw-sec-rg/providers/Microsoft.Network/virtualNetworks/myVNet/subnets/mySubnet'}
    }],
    web_application_firewall_configuration=waf_config
)

app_gateway = network_client.application_gateways.begin_create_or_update(
    resource_group, gateway_name, app_gateway_params).result()

print(f"Application Gateway '{gateway_name}' with WAF enabled created successfully!")

