#!/usr/bin/env python3
"""
TurkeyBite Setup Script

This script helps set up TurkeyBite in different deployment configurations:
- Development (all components on one machine)
- Small Scale (2-node setup)
- Full Scale (distributed deployment)

It generates appropriate docker-compose.yml and configuration files based on user input.
"""

import os
import sys
import yaml
import getpass
import shutil
import secrets
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Custom YAML representer for None values in volume definitions
def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')

# Register the custom representer
yaml.add_representer(type(None), represent_none)

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class TurkeyBiteSetup:
    """Main class for TurkeyBite setup"""

    def __init__(self):
        self.components = []
        self.node_type = ""
        self.is_distributed = False
        self.deployment_type = ""
        self.valkey_host = "valkey"
        self.opensearch_host = "opensearch"
        self.opensearch_admin_password = "Changeit12345!"  # Default OpenSearch admin password
        self.enable_dns_lookups = False
        self.dns_resolver = "172.172.0.100"  # Default resolver (Bind9 container)
        self.use_opensearch = True  # Default to using OpenSearch
        self.use_syslog = False     # Default to not using Syslog
        self.syslog_host = "graylog"
        self.syslog_port = 514
        self.base_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        self.support_dir = self.base_dir / "src" / "support"
        self.config_file = "config.yaml"
        self.env_file = ".env"
        self.compose_file = "docker-compose.yml"
        
        # Create base directories
        self.ensure_directories()

    def print_header(self):
        """Print a header with the tool name"""
        header = "TurkeyBite Setup"
        print("\n" + "=" * 40)
        print(f"{Colors.HEADER}{Colors.BOLD}{header.center(40)}{Colors.ENDC}")
        print("=" * 40 + "\n")

    def print_footer(self):
        """Print a footer to indicate completion"""
        footer = "Setup Complete!"
        print("\n" + "=" * 40)
        print(f"{Colors.GREEN}{Colors.BOLD}{footer.center(40)}{Colors.ENDC}")
        print("=" * 40 + "\n")

    def print_step(self, step: str):
        """Print a step in the setup process"""
        print(f"\n{Colors.BLUE}{Colors.BOLD}{step}{Colors.ENDC}")

    def print_success(self, message: str):
        """Print a success message"""
        print(f"{Colors.GREEN}✓ {message}{Colors.ENDC}")

    def print_error(self, message: str):
        """Print an error message"""
        print(f"{Colors.RED}✗ {message}{Colors.ENDC}")

    def print_info(self, message: str):
        """Print an info message"""
        print(f"{Colors.YELLOW}ℹ {message}{Colors.ENDC}")

    def prompt(self, message: str, options: Optional[List[str]] = None) -> str:
        """Prompt the user for input, optionally with numbered options"""
        if options:
            print(f"{message}")
            for i, option in enumerate(options, 1):
                print(f"{i}) {option}")
            while True:
                choice = input(f"Select [1-{len(options)}]: ")
                try:
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(options):
                        return options[choice_num - 1]
                    else:
                        self.print_error(f"Please select a number between 1 and {len(options)}")
                except ValueError:
                    self.print_error("Please enter a number")
        else:
            return input(f"{message}: ")

    def prompt_yes_no(self, message: str, default: bool = True) -> bool:
        """Prompt the user for a yes/no answer"""
        default_str = "Y/n" if default else "y/N"
        while True:
            response = input(f"{message} [{default_str}]: ").strip().lower()
            if not response:
                return default
            if response in ['y', 'yes']:
                return True
            if response in ['n', 'no']:
                return False
            self.print_error("Please enter 'y' or 'n'")

    def ensure_directories(self):
        """Ensure required directories exist"""
        dirs = [
            self.base_dir / "vols" / "bind",
            self.base_dir / "vols" / "opensearch",
            self.base_dir / "vols" / "valkey"
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)

    def load_yaml(self, file_path: Path) -> Dict:
        """Load YAML data from a file"""
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)

    def save_yaml(self, file_path: Path, data: Dict):
        """Save YAML data to a file"""
        with open(file_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def setup_valkey(self):
        """Set up Valkey password"""
        self.print_step("Setting up Valkey password")
        
        # Create secrets directory if it doesn't exist
        secrets_dir = self.base_dir / "vols" / "secrets"
        os.makedirs(secrets_dir, exist_ok=True)
        password_file = secrets_dir / "valkey_password.txt"
        
        # Check if this is a distributed deployment where Valkey runs on a different node
        external_valkey = self.is_distributed and 'valkey' not in self.components
        
        if external_valkey:
            # Valkey is on another node, so we need to prompt for the existing password
            self.print_info("Valkey is running on an external node. You need to provide the Valkey password.")
            
            if password_file.exists():
                with open(password_file, 'r') as f:
                    current_password = f.read().strip()
                self.print_info("Current password is set. Enter the same value to keep it or a new value to change it.")
            else:
                current_password = None
                
            # Keep prompting until we get a non-empty password
            while True:
                entered_password = getpass.getpass("Enter the Valkey password from the Data Node: ")
                if entered_password:
                    break
                self.print_error("Password cannot be empty. Please try again.")
                
            # Save the entered password
            with open(password_file, 'w') as f:
                f.write(entered_password)
                
            self.print_success("Valkey password saved.")
        else:
            # This node runs Valkey or it's a non-distributed setup
            if password_file.exists():
                self.print_success("Valkey password file found.")
                if self.prompt_yes_no("Generate a new password?", default=False):
                    new_password = self.generate_password()
                    with open(password_file, 'w') as f:
                        f.write(new_password)
            else:
                password = self.generate_password()
                with open(password_file, 'w') as f:
                    f.write(password)
            
            # Display the password for the user to save
            with open(password_file, 'r') as f:
                password = f.read().strip()
                
            self.print_info("IMPORTANT: Save this password for other nodes:")
            print(password)

    def generate_password(self, length: int = 128) -> str:
        """Generate a secure password"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password

    def setup_config(self):
        """Set up the configuration file"""
        # Skip config creation if no TurkeyBite components are present
        if not any(comp in self.components for comp in ['core', 'librarian', 'worker']):
            self.print_info("No TurkeyBite application components selected, skipping config.yaml creation.")
            return
        
        example_config = self.support_dir / "config.example.yaml"
        target_config = self.base_dir / self.config_file
        
        if target_config.exists():
            self.print_step(f"Configuration file {self.config_file} exists.")
            if not self.prompt_yes_no("Do you want to update it?", default=False):
                return
        
        # Copy and modify the config
        config_data = self.load_yaml(example_config)
        
        # Update Redis/Valkey connection settings
        config_data['redis']['host'] = self.valkey_host
        
        # Update DNS lookup settings
        config_data['processor']['dns']['lookup_ips'] = self.enable_dns_lookups
        if self.enable_dns_lookups:
            # Set the resolver to either the bind container IP or user-provided IP
            config_data['processor']['dns']['resolvers'] = [self.dns_resolver]
        
        # Update output settings
        # OpenSearch
        config_data['processor']['elastic']['enable'] = self.use_opensearch
        if self.use_opensearch:
            # Update OpenSearch connection details with admin password and host
            # Always use HTTPS for OpenSearch connections
            opensearch_uri = f"https://{self.opensearch_host}:9200"
            
            # Reset hosts array if needed for distributed deployments
            if self.is_distributed and self.opensearch_host != "opensearch":
                config_data['processor']['elastic']['hosts'] = [
                    {
                        "uri": opensearch_uri,
                        "username": "admin",
                        "password": self.opensearch_admin_password
                    }
                ]
            else:
                # Update existing hosts with password and possibly URI
                for i, host in enumerate(config_data['processor']['elastic']['hosts']):
                    if isinstance(host, dict) and 'uri' in host and 'username' in host and 'password' in host:
                        config_data['processor']['elastic']['hosts'][i]['password'] = self.opensearch_admin_password
                        if self.opensearch_host != "opensearch":
                            config_data['processor']['elastic']['hosts'][i]['uri'] = opensearch_uri
        
        # Syslog
        config_data['processor']['syslog']['enable'] = self.use_syslog
        if self.use_syslog:
            config_data['processor']['syslog']['host'] = self.syslog_host
            config_data['processor']['syslog']['port'] = self.syslog_port
        
        # Save the updated config
        self.save_yaml(target_config, config_data)
        self.print_success(f"Configuration file {self.config_file} updated.")
        
        # Show a summary of the configuration
        self.print_step("Configuration Summary:")
        print(f"  DNS Lookups: {'Enabled' if self.enable_dns_lookups else 'Disabled'}")
        print(f"  OpenSearch Output: {'Enabled' if self.use_opensearch else 'Disabled'}")
        print(f"  Syslog Output: {'Enabled' if self.use_syslog else 'Disabled'}")
        if self.use_syslog:
            print(f"    Syslog Host: {self.syslog_host}:{self.syslog_port}")
        print(f"  Valkey Host: {self.valkey_host}")
        if self.use_opensearch:
            print(f"  OpenSearch Host: {self.opensearch_host}")
        print(f"  Components: {', '.join(self.components)}")

    def setup_env(self):
        """Set up the environment file based on components being deployed"""
        example_env = self.support_dir / "example.env"
        target_env = self.base_dir / self.env_file
        
        if target_env.exists():
            self.print_step(f"Environment file {self.env_file} exists.")
            if not self.prompt_yes_no("Do you want to update it?", default=False):
                return
        
        # Define component-specific environment variables
        component_env_vars = {
            # Common variables for all deployments
            'common': [
                "# TurkeyBite Environment Variables\n",
                "TZ=UTC\n"
            ],
            # Core/librarian/worker need Valkey connection details
            'core': [
                f"VALKEY_HOST={self.valkey_host}\n"
            ],
            'librarian': [
                "TURKEYBITE_HOSTS_INTERVAL_MIN=720\n",
                "TURKEYBITE_IGNORELIST_INTERVAL_MIN=5\n"
            ],
            'worker': [
                "TURKEYBITE_WORKER_PROCS=2\n"
            ],
            # Valkey specific settings
            'valkey': [
                "VALKEY_PORT=6379\n",
                "VALKEY_LOGLEVEL=warning\n",
                "VALKEY_SAVE_INTERVAL_SECONDS=60\n",
                "VALKEY_SAVE_KEYS=1000\n"
            ],
            # OpenSearch specific settings
            'opensearch': [
                "OPENSEARCH_PORT=9200\n",
                "OPENSEARCH_PERFORMANCE_PORT=9600\n",
                "OPENSEARCH_DASHBOARD_PORT=5601\n",
                f"OPENSEARCH_INITIAL_ADMIN_PASSWORD={self.opensearch_admin_password}\n",
                f"OPENSEARCH_HOSTS='[\"https://{self.opensearch_host}:9200\"]'\n",
                "bootstrap.memory_lock=true\n",
                f"node.name=${{OPENSEARCH_HOST}}\n",
                "discovery.type=single-node\n",
                "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m\n"
            ],
            # Bind9 specific settings
            'bind': [
                "BIND9_IP=172.172.0.100\n"
            ]
        }
        
        # If using OpenSearch for output, all components need this
        if self.use_opensearch:
            component_env_vars['common'].append(f"OPENSEARCH_HOST={self.opensearch_host}\n")
        
        # If using Syslog for output, all components need this
        if self.use_syslog:
            component_env_vars['common'].append(f"SYSLOG_HOST={self.syslog_host}\n")
            component_env_vars['common'].append(f"SYSLOG_PORT={self.syslog_port}\n")
        
        # Initialize environment variable content list
        env_content = []
        
        # Determine which sections to include based on components
        sections_to_include = ['common']
        
        # Include core section with Valkey connection details if we have app components,
        # but skip for search nodes since they don't need Valkey info
        if any(comp in self.components for comp in ['core', 'librarian', 'worker']) and self.node_type != 'search':
            sections_to_include.append('core')
        
        # Add component variables for direct services
        for component in ['librarian', 'worker', 'valkey', 'opensearch', 'bind']:
            if component in self.components:
                sections_to_include.append(component)
        
        # Add all environment variables from included sections
        for section in sections_to_include:
            if section in component_env_vars:
                env_content.extend(component_env_vars[section])
        
        # Write the updated content
        with open(target_env, 'w') as f:
            f.writelines(env_content)
        
        self.print_success(f"Environment file {self.env_file} updated.")

        if self.use_syslog:
            self.print_info(f"Syslog configuration added: {self.syslog_host}:{self.syslog_port}")

    def setup_bind_config(self):
        """Setup Bind9 configuration files"""
        # Only run if bind is part of the components and DNS lookups are enabled
        if "bind" not in self.components:
            return
            
        self.print_step("Setting up Bind9 configuration...")
        bind_dir = self.base_dir / "vols" / "bind"
        
        # Create the bind directory if it doesn't exist
        os.makedirs(bind_dir, exist_ok=True)
        
        # Copy the example files if they don't exist
        for file_name in ["named.conf.local", "named.conf.options", "slave.conf"]:
            target_file = bind_dir / file_name
            example_file = self.support_dir / "bind" / file_name
            
            if target_file.exists():
                if not self.prompt_yes_no(f"{file_name} found. Overwrite?", default=False):
                    continue
                    
            shutil.copy(example_file, target_file)
        
        self.print_success("Bind9 configuration files set up.")
        self.print_info("Remember to customize your DNS configuration if needed.")

    def extract_service(self, compose_data: Dict, service_name: str) -> Dict:
        """Extract a service from the compose data"""
        if 'services' in compose_data and service_name in compose_data['services']:
            return {service_name: compose_data['services'][service_name]}
        return {}
    
    def setup_docker_compose(self):
        """Set up the Docker Compose file"""
        self.print_step("Setting up Docker Compose")
        
        target_compose = self.base_dir / self.compose_file
        fragments_dir = self.support_dir / "compose-fragments"
        
        # All deployment types (Development, Small Scale, Full Scale) now use the same approach
        # We'll always generate from fragments for consistency across deployment modes
        
        # Start with the base compose file
        new_compose = {
            'services': {},
            'volumes': {}
        }
        
        # Volume mapping for each component
        volume_mapping = {
            'opensearch': ['opensearch_data'],
            'valkey': ['valkey_data'],
            'bind': ['bind9_cache']
        }
        
        # Load network configuration from fragment
        network_fragment = fragments_dir / "network.yml"
        if network_fragment.exists():
            try:
                network_data = self.load_yaml(network_fragment)
                if 'networks' in network_data:
                    new_compose['networks'] = network_data['networks']
                else:
                    self.print_error(f"Network fragment exists but doesn't contain networks configuration.")
                    # Fallback to default network config
                    new_compose['networks'] = {
                        'tb-net': {
                            'driver': 'bridge',
                            'ipam': {
                                'driver': 'default',
                                'config': [{
                                    'subnet': '172.172.0.0/24',
                                    'gateway': '172.172.0.1'
                                }]
                            }
                        }
                    }
            except Exception as e:
                self.print_error(f"Error loading network fragment: {str(e)}")
                # Fallback to default network config
                new_compose['networks'] = {
                    'tb-net': {
                        'driver': 'bridge',
                        'ipam': {
                            'driver': 'default',
                            'config': [{
                                'subnet': '172.172.0.0/24',
                                'gateway': '172.172.0.1'
                            }]
                        }
                    }
                }
        else:
            self.print_info("Network fragment not found, using default network configuration.")
            # Default network config
            new_compose['networks'] = {
                'tb-net': {
                    'driver': 'bridge',
                    'ipam': {
                        'driver': 'default',
                        'config': [{
                            'subnet': '172.172.0.0/24',
                            'gateway': '172.172.0.1'
                        }]
                    }
                }
            }
        
        # Volume mapping for each component
        volume_mapping = {
            'bind': ['bind9_cache'],
            'valkey': ['valkey_data'],
            'opensearch': ['opensearch_data']
        }
        
        # Load and merge component fragments if they exist
        for component in self.components:
            fragment_file = fragments_dir / f"{component}.yml"
            if fragment_file.exists():
                try:
                    component_data = self.load_yaml(fragment_file)
                    # Add services from this component
                    if 'services' in component_data:
                        for service_name, service_config in component_data['services'].items():
                            # Make a copy of the service config so we can modify it
                            service_config = service_config.copy()
                            
                            # Remove config.yaml volume mount if it doesn't exist or isn't needed
                            if not Path(self.base_dir / self.config_file).exists() and 'volumes' in service_config:
                                config_mount_found = False
                                # Find and remove the config.yaml volume mount if present
                                for i, volume in enumerate(service_config['volumes']):
                                    if isinstance(volume, str) and '/turkey-bite/config.yaml' in volume:
                                        config_mount_found = True
                                        service_config['volumes'].pop(i)
                                        break
                            
                            # Special handling for OpenSearch ports based on deployment type
                            if service_name == 'opensearch':
                                # For search nodes or full-scale OpenSearch deployments,
                                # expose ports externally with 'ports' directive
                                if self.node_type == 'search' or (self.is_distributed and component == 'opensearch'):
                                    # Remove 'expose' directive if it exists
                                    if 'expose' in service_config:
                                        del service_config['expose']
                                    
                                    # Add 'ports' directive for external access
                                    service_config['ports'] = [
                                        "${OPENSEARCH_PORT:-9200}:9200",
                                        "${OPENSEARCH_PERFORMANCE_PORT:-9600}:9600"
                                    ]
                            
                            # Special handling for distributed deployments
                            if self.is_distributed and 'depends_on' in service_config:
                                # In distributed deployments, we need to remove dependencies on services
                                # that are running on other nodes
                                
                                # Create a copy of the depends_on section to modify
                                depends_on = service_config.get('depends_on', {}).copy()
                                
                                # List of services that might be on other nodes in distributed setups
                                external_services = []
                                
                                # Valkey might be on a Data Node
                                if 'valkey' not in self.components and 'valkey' in depends_on:
                                    external_services.append('valkey')
                                    
                                # OpenSearch might be on a Search Node
                                if 'opensearch' not in self.components and 'opensearch' in depends_on:
                                    external_services.append('opensearch')
                                
                                # Remove external service dependencies
                                for service in external_services:
                                    if service in depends_on:
                                        del depends_on[service]
                                
                                # Update the service config with modified dependencies
                                # Only keep the depends_on section if there are still local dependencies
                                if depends_on:
                                    service_config['depends_on'] = depends_on
                                else:
                                    # Remove depends_on completely if it's empty
                                    if 'depends_on' in service_config:
                                        del service_config['depends_on']
                            
                            new_compose['services'][service_name] = service_config
                            
                            # For distributed deployment, update connection settings
                            if self.is_distributed:
                                if component in ['core', 'worker', 'librarian']:
                                    if 'environment' in new_compose['services'][service_name]:
                                        # Update environment vars for Redis connection
                                        env = new_compose['services'][service_name]['environment']
                                        for i, var in enumerate(env):
                                            if var.startswith('REDIS_HOST='):
                                                env[i] = f"REDIS_HOST={self.valkey_host}"
                                            elif var.startswith('ELASTICSEARCH_HOST='):
                                                env[i] = f"ELASTICSEARCH_HOST={self.opensearch_host}"
                except Exception as e:
                    self.print_error(f"Error processing {component} fragment: {str(e)}")
            else:
                self.print_info(f"No fragment found for {component}. Using defaults.")
                
                # Add basic service definitions for components without fragments
                if component == 'core':
                    new_compose['services']['core'] = {
                        'image': 'turkeybite/core:latest',
                        'restart': 'unless-stopped',
                        'networks': ['tb-net'],
                        'environment': [
                            f"REDIS_HOST={self.valkey_host}",
                            "REDIS_PORT=6379"
                        ]
                    }
                elif component == 'worker':
                    new_compose['services']['worker'] = {
                        'image': 'turkeybite/worker:latest',
                        'restart': 'unless-stopped',
                        'networks': ['tb-net'],
                        'environment': [
                            f"REDIS_HOST={self.valkey_host}",
                            "REDIS_PORT=6379"
                        ]
                    }
                elif component == 'librarian':
                    new_compose['services']['librarian'] = {
                        'image': 'turkeybite/librarian:latest',
                        'restart': 'unless-stopped',
                        'networks': ['tb-net'],
                        'environment': [
                            f"REDIS_HOST={self.valkey_host}",
                            "REDIS_PORT=6379"
                        ]
                    }
                elif component == 'bind':
                    new_compose['services']['bind'] = {
                        'image': 'ubuntu/bind9:latest',
                        'restart': 'unless-stopped',
                        'networks': ['tb-net'],
                        'volumes': ['./vols/bind:/etc/bind']
                    }
                elif component == 'valkey':
                    new_compose['services']['valkey'] = {
                        'image': 'valkey/valkey:latest',
                        'restart': 'unless-stopped',
                        'networks': ['tb-net'],
                        'volumes': ['valkey_data:/data']
                    }
                elif component == 'opensearch':
                    new_compose['services']['opensearch'] = {
                        'image': 'opensearchproject/opensearch:latest',
                        'restart': 'unless-stopped',
                        'networks': ['tb-net'],
                        'volumes': ['opensearch_data:/usr/share/opensearch/data'],
                        'environment': [
                            "discovery.type=single-node",
                            "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
                        ]
                    }
        
        # Add volumes based on components
        for component, volumes in volume_mapping.items():
            if component in self.components:
                for volume in volumes:
                    new_compose['volumes'][volume] = None  # We'll handle this specially
        
        # Add the secrets section if Valkey is included
        if 'valkey' in self.components:
            new_compose['secrets'] = {
                'valkey_password': {
                    'file': 'vols/secrets/valkey_password.txt'
                }
            }
        
        # Create dictionary with sections in the desired order
        compose_without_networks = {}
        
        # 1. Services first
        if 'services' in new_compose:
            compose_without_networks['services'] = new_compose['services']
        else:
            # Always include services section even if empty
            compose_without_networks['services'] = {}
        
        # 2. Secrets second
        if 'secrets' in new_compose:
            compose_without_networks['secrets'] = new_compose['secrets']
        
        # 3. Volumes third (only if not empty)
        if 'volumes' in new_compose and new_compose['volumes']:
            # Only add volumes section if there are actually volumes defined
            compose_without_networks['volumes'] = new_compose['volumes']
        
        # Write the main parts of the compose file first, preserving order
        with open(target_compose, 'w') as f:
            yaml.dump(compose_without_networks, f, default_flow_style=False, sort_keys=False)
            
        # Append network configuration at the end
        network_config = {
            'networks': {
                'tb-net': {
                    'driver': 'bridge',
                    'ipam': {
                        'driver': 'default',
                        'config': [{
                            'subnet': '172.172.0.0/24',
                            'gateway': '172.172.0.1'
                        }]
                    }
                }
            }
        }
        
        # Append networks section to the compose file
        with open(target_compose, 'a') as f:
            yaml.dump(network_config, f, default_flow_style=False, sort_keys=False)
        
        self.print_success(f"Docker Compose file {self.compose_file} created.")

    def setup_opensearch_password(self):
        """Set up the OpenSearch admin password"""
        self.print_step("OpenSearch Admin Password Configuration")
        
        self.print_info("For security reasons, you must set an OpenSearch admin password.")
        
        # Custom password with validation
        while True:
            password = self.prompt("Enter OpenSearch admin password (min 8 chars, including uppercase, lowercase, and special character)")
            
            # Check if it's the default password
            if password == "Changeit12345!":
                if self.prompt_yes_no("Using the default password (Changeit12345!) is not recommended. Are you sure?", default=False):
                    self.print_info("Using default password. IMPORTANT: Change this password for production use!")
                else:
                    continue
            
            # Perform validation
            if len(password) < 8:
                self.print_error("Password must be at least 8 characters long.")
                continue
            
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_special = any(not c.isalnum() for c in password)
            
            if not (has_upper and has_lower and has_special):
                self.print_error("Password must contain at least one uppercase letter, one lowercase letter, and one special character.")
                continue
            
            # Confirm password
            confirm = self.prompt("Confirm password")
            if password != confirm:
                self.print_error("Passwords do not match.")
                continue
            
            self.opensearch_admin_password = password
            self.print_success("OpenSearch admin password set successfully.")
            break

    def prompt_for_client_lookups(self):
        """Ask if client IP lookups should be enabled"""
        self.print_step("Client IP Lookups Configuration")
        if self.prompt_yes_no("Enable DNS lookups for client IPs?", default=False):
            self.enable_dns_lookups = True
            # If bind is not already included, offer to add it
            if "bind" not in self.components:
                if self.prompt_yes_no("Include Bind9 DNS server for lookups?", default=True):
                    self.components.append("bind")
                    self.print_success("Added Bind9 to the deployment.")
                    # When using Bind9, we'll use its IP as the resolver
                    self.dns_resolver = "172.172.0.100"
                else:
                    # If not using Bind9, we need to ask for resolver IP
                    self.dns_resolver = self.prompt("Enter DNS resolver IP address")
                    self.print_success(f"Using external DNS resolver: {self.dns_resolver}")
            else:
                # Bind is already included, use its IP
                self.dns_resolver = "172.172.0.100"
        else:
            self.enable_dns_lookups = False
            # If bind was added just for lookups, ask if it should be removed
            if "bind" in self.components:
                if self.prompt_yes_no("Remove Bind9 since lookups are disabled?", default=False):
                    self.components.remove("bind")
                    self.print_success("Removed Bind9 from the deployment.")
    
    def configure_output_options(self):
        """Configure output options (OpenSearch and/or Syslog)"""
        self.print_step("Output Configuration")
        self.use_opensearch = self.prompt_yes_no("Send output to OpenSearch?", default=True)
        self.use_syslog = self.prompt_yes_no("Send output to Syslog?", default=False)
        
        if self.use_syslog:
            self.syslog_host = self.prompt("Enter Syslog host")
            while True:
                try:
                    self.syslog_port = int(self.prompt("Enter Syslog port (default: 514)") or "514")
                    if 1 <= self.syslog_port <= 65535:
                        break
                    self.print_error("Port must be between 1 and 65535.")
                except ValueError:
                    self.print_error("Please enter a valid port number.")
            
            self.print_success(f"Syslog output configured: {self.syslog_host}:{self.syslog_port}")

    def setup_development(self):
        """Setup for development mode (all components)"""
        self.deployment_type = "Development"
        self.components = ["core", "librarian", "worker", "valkey", "opensearch"]
        self.node_type = "dev"
        self.is_distributed = False
        self.use_opensearch = True
        self.use_syslog = False
        
        # Ask about client IP lookups and bind inclusion
        self.prompt_for_client_lookups()

    def setup_small_scale(self):
        """Setup for small scale deployment (2 nodes)"""
        self.deployment_type = "Small Scale"
        self.is_distributed = True
        
        node_type = self.prompt("Node Selection", [
            "Application Node (Core + Librarian + Worker + Valkey)",
            "Search Node (OpenSearch + Dashboards)"
        ])
        
        if "Application Node" in node_type:
            self.node_type = "app"
            self.components = ["core", "librarian", "worker", "valkey"]
            
            # Configure DNS lookups
            self.prompt_for_client_lookups()
            
            # Configure output options first
            self.configure_output_options()
            
            # Only ask for OpenSearch host if it's being used
            if self.use_opensearch:
                self.opensearch_host = self.prompt("Enter the OpenSearch node IP or hostname")
            
        elif "Search Node" in node_type:
            self.node_type = "search"
            self.components = ["opensearch"]
            self.use_opensearch = True
            self.use_syslog = False
            # DNS lookups not applicable for the search node
            self.enable_dns_lookups = False

    def setup_full_scale(self):
        """Setup for full scale distributed deployment"""
        self.deployment_type = "Full Scale"
        self.is_distributed = True
        self.use_opensearch = True
        self.use_syslog = False
        
        node_type = self.prompt("Node Type", [
            "Core Node (Core + Librarian)",
            "Worker Node (Worker)",
            "Data Node (Valkey)",
            "Search Node (OpenSearch + Dashboards)"
        ])
        
        if "Core Node" in node_type:
            self.node_type = "core"
            self.components = ["core", "librarian"]
            # Configure output options
            self.configure_output_options()
            # DNS lookups don't apply directly to core node
            self.enable_dns_lookups = False
            
        elif "Worker Node" in node_type:
            self.node_type = "worker"
            self.components = ["worker"]
            # Configure DNS lookups for worker node
            self.prompt_for_client_lookups()
            # Configure output options
            self.configure_output_options()
                
        elif "Data Node" in node_type:
            self.node_type = "data"
            self.components = ["valkey"]
            # No specific configuration for data node
            self.enable_dns_lookups = False
            
        elif "Search Node" in node_type:
            self.node_type = "search"
            self.components = ["opensearch"]
            # No DNS lookups for search node
            self.enable_dns_lookups = False
        
        # For distributed setups, get connection information
        # Skip Valkey host prompt for Search Nodes as they don't need it
        if self.node_type != "data" and self.node_type != "search" and "valkey" not in self.components:
            # Valkey is external, prompt for connection info
            self.valkey_host = self.prompt("Enter Valkey host (IP or hostname)")
            
        if self.node_type in ["core", "worker"] and "opensearch" not in self.components and self.use_opensearch:
            self.opensearch_host = self.prompt("Enter OpenSearch host (IP or hostname)")

    def run(self):
        """Run the setup"""
        self.print_header()
        
        self.print_step("Deployment Type")
        deployment_type = self.prompt("Select", [
            "Development (all components on one machine)",
            "Small Scale (2-node setup: Application node + OpenSearch node)",
            "Full Scale (distributed components, custom configuration)"
        ])
        
        if "Development" in deployment_type:
            self.setup_development()
            # If not already asked in setup_development, ask about output options
            if not hasattr(self, 'configure_output_options_called'):
                self.configure_output_options()
                setattr(self, 'configure_output_options_called', True)
        elif "Small Scale" in deployment_type:
            self.setup_small_scale()
        elif "Full Scale" in deployment_type:
            self.setup_full_scale()
        
        self.print_info(f"Components selected: {', '.join(self.components)}")
        
        # Setup Valkey password and configuration only if needed
        # Skip for Search Nodes as they don't need Valkey access
        if self.node_type != 'search':
            self.setup_valkey()
        
        # Setup OpenSearch admin password if using OpenSearch
        if self.use_opensearch:
            self.setup_opensearch_password()
        
        # Setup the main configuration files
        self.setup_config()
        self.setup_env()
        
        # Setup Bind9 only if it's in the components
        if "bind" in self.components:
            self.setup_bind_config()
        
        # Generate the docker-compose file
        self.setup_docker_compose()
        
        self.print_footer()
        
        # Provide more detailed next steps based on the configuration
        next_steps = [
            "1. Review and edit the config.yaml file",
            "2. Review and edit the .env file",
            "3. Start the containers with: docker compose up -d"
        ]
        
        # Add specific notes depending on what was configured
        if self.enable_dns_lookups and "bind" in self.components:
            next_steps.append("4. Configure your DNS zones in bind/named.conf.local if needed")
        
        if self.use_syslog:
            next_steps.append(f"5. Ensure your Syslog server at {self.syslog_host}:{self.syslog_port} is ready to receive logs")
        
        self.print_info("Next steps:\n" + "\n".join(next_steps))


if __name__ == "__main__":
    setup = TurkeyBiteSetup()
    setup.run()
