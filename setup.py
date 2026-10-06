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
import re
import sys
import yaml
import getpass
import shutil
import secrets
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# The OpenSearch admin password TurkeyBite used to ship with. Anyone who has read
# this repository knows it, and the admin account can read and delete every
# event, so the workers and the librarian refuse it and so does this script.
DEFAULT_OPENSEARCH_PASSWORD = "Changeit12345!"

# The symbols a new OpenSearch password may use. Each survives unquoted in .env,
# where docker compose would expand $ and cut at #, and in the opensearch
# healthcheck, which compose pastes into an unquoted shell command, where & ; |
# ( ) < > * ? and quotes would break it and leave OpenSearch marked unhealthy.
OPENSEARCH_PASSWORD_SYMBOLS = "-_.+=,%@:^!"


def opensearch_password_problem(password: str) -> Optional[str]:
    """Why a new OpenSearch admin password would be refused, or None.

    OpenSearch 2.12 and later refuse an initial admin password without eight
    characters, upper and lower case letters, a digit and a symbol, and then
    score what is left for strength. This checks the rules it states; the
    strength score it can only check itself.
    """
    if password.strip() == DEFAULT_OPENSEARCH_PASSWORD:
        return (f"{DEFAULT_OPENSEARCH_PASSWORD} is the password TurkeyBite used to ship "
                "with, which anyone can look up. Choose another.")
    if len(password) < 8:
        return "The password must be at least 8 characters long."
    if not (any(c.isupper() for c in password) and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)):
        return "The password must contain an uppercase letter, a lowercase letter and a digit."
    others = set(c for c in password if not c.isalnum())
    if not others:
        return f"The password must contain one of these symbols: {OPENSEARCH_PASSWORD_SYMBOLS}"
    unusable = others - set(OPENSEARCH_PASSWORD_SYMBOLS)
    if unusable:
        return (f"The password cannot contain {''.join(sorted(unusable))!r}, which .env or "
                f"the OpenSearch healthcheck would change. Use these symbols: "
                f"{OPENSEARCH_PASSWORD_SYMBOLS}")
    return None


def generate_opensearch_password(length: int = 32) -> str:
    """A random OpenSearch admin password that meets its rules.

    One character from each class OpenSearch requires, the rest from all of
    them, shuffled so the classes do not sit in a predictable order.
    """
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = lower.upper()
    digits = "0123456789"
    every = lower + upper + digits + OPENSEARCH_PASSWORD_SYMBOLS
    chars = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digits),
             secrets.choice(OPENSEARCH_PASSWORD_SYMBOLS)]
    chars += [secrets.choice(every) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)


# Days OpenSearch keeps each daily index, unless the operator says otherwise.
# The same as libtb.retention.SUGGESTED_DAYS, which a test checks. Only a
# suggestion: the librarian does nothing while the variable is unset.
DEFAULT_RETENTION_DAYS = 90


def retention_days_problem(answer: str) -> Optional[str]:
    """Why an answer to the retention prompt is refused, or None"""
    if not re.fullmatch(r"[0-9]+", answer.strip()):
        return "Enter a whole number of days, or 0 to keep indices forever."
    return None


def section(data: Dict, *keys: str) -> Dict:
    """The nested mapping at keys in data, created where missing"""
    for key in keys:
        if not isinstance(data.get(key), dict):
            data[key] = {}
        data = data[key]
    return data


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
        # Chosen or generated in setup_opensearch_password; there is no default
        self.opensearch_admin_password = None
        self.retention_days = DEFAULT_RETENTION_DAYS
        # Whether an existing config.yaml and .env may be updated, asked once
        # before either is written, see decide_updates
        self.update_config = True
        self.update_env = True
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
        """Set up the configuration file.

        A new config.yaml starts from the example. An existing one starts from
        itself, so a rerun changes only the settings this script asks about and
        keeps everything else an operator set, such as processor.privacy or a
        host's verify_certs and ca_certs. Comments do not survive the rewrite.
        """
        # Skip config creation if no TurkeyBite components are present
        if not self.runs_app():
            self.print_info("No TurkeyBite application components selected, skipping config.yaml creation.")
            return

        example_config = self.support_dir / "config.example.yaml"
        target_config = self.base_dir / self.config_file

        if target_config.exists():
            if not self.update_config:
                return
            config_data = self.load_yaml(target_config) or {}
        else:
            config_data = self.load_yaml(example_config)

        # Update Redis/Valkey connection settings
        section(config_data, 'redis')['host'] = self.valkey_host

        # Update DNS lookup settings
        dns = section(config_data, 'processor', 'dns')
        dns['lookup_ips'] = self.enable_dns_lookups
        if self.enable_dns_lookups:
            # Set the resolver to either the bind container IP or user-provided IP
            dns['resolvers'] = [self.dns_resolver]

        # Update output settings
        # OpenSearch
        elastic = section(config_data, 'processor', 'elastic')
        elastic['enable'] = self.use_opensearch
        if self.use_opensearch:
            # Always use HTTPS for OpenSearch connections
            opensearch_uri = f"https://{self.opensearch_host}:9200"
            hosts = [h for h in (elastic.get('hosts') or []) if isinstance(h, dict)]
            if not hosts:
                hosts = [{"uri": opensearch_uri, "username": "admin"}]
            elif self.opensearch_host != "opensearch":
                if len(hosts) == 1:
                    hosts[0]['uri'] = opensearch_uri
                else:
                    self.print_info(f"{self.config_file} lists {len(hosts)} OpenSearch hosts; "
                                    "their addresses are left as they are.")
            for host in hosts:
                # Every host is the same cluster, so has the same admin password.
                # A host signing in as another account keeps its own password,
                # which setup never asked for. Anything else on the host, such as
                # verify_certs, is kept.
                host.setdefault('username', 'admin')
                if host['username'] == 'admin':
                    host['password'] = self.opensearch_admin_password
                else:
                    self.print_info(f"OpenSearch host {host.get('uri', '')} signs in as "
                                    f"{host['username']}; its password is left as it is.")
            elastic['hosts'] = hosts

        # Syslog
        syslog = section(config_data, 'processor', 'syslog')
        syslog['enable'] = self.use_syslog
        if self.use_syslog:
            syslog['host'] = self.syslog_host
            syslog['port'] = self.syslog_port

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

    def env_settings(self) -> List[Tuple[str, str, bool]]:
        """What .env should hold for this node, as (key, value, managed).

        Managed settings come from the answers given here and are always
        written. The rest are starting values, written only where .env does
        not have the key yet, so a rerun keeps whatever an operator changed.
        """
        app = self.runs_app() and self.node_type != 'search'
        settings = [("TZ", "UTC", False)]
        if self.use_opensearch:
            settings += [("OPENSEARCH_HOST", self.opensearch_host, True),
                         ("OPENSEARCH_USERNAME", "admin", False),
                         ("OPENSEARCH_PASSWORD", self.opensearch_admin_password, True)]
        if self.use_syslog:
            settings += [("SYSLOG_HOST", self.syslog_host, True),
                         ("SYSLOG_PORT", str(self.syslog_port), True)]
        # Core/librarian/worker need Valkey connection details, but search
        # nodes do not
        if app:
            settings += [("VALKEY_HOST", self.valkey_host, True)]
        if "librarian" in self.components:
            settings += [("TURKEYBITE_HOSTS_INTERVAL_MIN", "720", False),
                         ("TURKEYBITE_IGNORELIST_INTERVAL_MIN", "5", False)]
            if self.use_opensearch:
                settings += [("TURKEYBITE_RETENTION_DAYS", str(self.retention_days), True)]
        if "worker" in self.components:
            settings += [("TURKEYBITE_WORKER_PROCS", "2", False)]
        if "valkey" in self.components:
            settings += [("VALKEY_PORT", "6379", False),
                         ("VALKEY_LOGLEVEL", "warning", False),
                         ("VALKEY_SAVE_INTERVAL_SECONDS", "60", False),
                         ("VALKEY_SAVE_KEYS", "1000", False)]
        if "opensearch" in self.components:
            settings += [("OPENSEARCH_PORT", "9200", False),
                         ("OPENSEARCH_PERFORMANCE_PORT", "9600", False),
                         ("OPENSEARCH_DASHBOARD_PORT", "5601", False),
                         ("OPENSEARCH_INITIAL_ADMIN_PASSWORD", self.opensearch_admin_password, True),
                         ("OPENSEARCH_HOSTS", f"'[\"https://{self.opensearch_host}:9200\"]'", True),
                         ("bootstrap.memory_lock", "true", False),
                         ("node.name", "${OPENSEARCH_HOST}", False),
                         ("discovery.type", "single-node", False),
                         ("OPENSEARCH_JAVA_OPTS", "-Xms512m -Xmx512m", False)]
        if "bind" in self.components:
            settings += [("BIND9_IP", "172.172.0.100", False)]
        return settings

    def setup_env(self):
        """Set up the environment file based on components being deployed.

        An existing .env is edited rather than replaced: the settings this
        script asks about are changed in place, keys it would add are added
        only if missing, and every other line, an OPENSEARCH_CA_CERT or a
        comment, is kept as it was.
        """
        target_env = self.base_dir / self.env_file
        settings = self.env_settings()

        if target_env.exists():
            if not self.update_env:
                return
            with open(target_env, 'r') as f:
                lines = f.readlines()
        else:
            lines = ["# TurkeyBite Environment Variables\n"]

        values = {key: (value, managed) for key, value, managed in settings}
        seen = set()
        for i, line in enumerate(lines):
            key = line.split('=', 1)[0].strip() if '=' in line and not line.lstrip().startswith('#') else None
            if key in values:
                seen.add(key)
                value, managed = values[key]
                if managed:
                    lines[i] = f"{key}={value}\n"
        if lines and not lines[-1].endswith('\n'):
            lines[-1] += '\n'
        lines += [f"{key}={value}\n" for key, value, _ in settings if key not in seen]

        # Write the updated content
        with open(target_env, 'w') as f:
            f.writelines(lines)

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

    def runs_app(self) -> bool:
        """True when this node runs a TurkeyBite container, so has a config.yaml"""
        return any(comp in self.components for comp in ['core', 'librarian', 'worker'])

    def existing_password(self) -> Optional[str]:
        """The OpenSearch admin password a previous run left, from .env or config.yaml"""
        found = (self.existing_env_value("OPENSEARCH_PASSWORD")
                 or self.existing_env_value("OPENSEARCH_INITIAL_ADMIN_PASSWORD"))
        target_config = self.base_dir / self.config_file
        if not found and target_config.exists():
            config = self.load_yaml(target_config) or {}
            for host in ((config.get('processor') or {}).get('elastic') or {}).get('hosts') or []:
                if (isinstance(host, dict) and host.get('password')
                        and host.get('username', 'admin') == 'admin'):
                    return str(host['password'])
        return found

    def decide_updates(self):
        """Asks once whether an existing config.yaml and .env may be updated.

        Asked before either is written, so a password can be kept from reaching
        only one of them, see keep_password_in_step.
        """
        if self.runs_app() and (self.base_dir / self.config_file).exists():
            self.print_step(f"Configuration file {self.config_file} exists.")
            self.update_config = self.prompt_yes_no("Do you want to update it?", default=False)
        if (self.base_dir / self.env_file).exists():
            self.print_step(f"Environment file {self.env_file} exists.")
            self.update_env = self.prompt_yes_no("Do you want to update it?", default=False)

    def keep_password_in_step(self, previous: Optional[str]) -> bool:
        """Stops a new OpenSearch password reaching only some of the files that hold it.

        .env holds it for the librarian and for OpenSearch's first start, and
        config.yaml for the workers. A new password written to one and not the
        other leaves them disagreeing, so if an existing file holding it is not
        to be updated the change is abandoned. Returns True when the password
        is changing.
        """
        new = self.opensearch_admin_password
        if new is None or previous is None or new == previous:
            return False
        declined = []
        if self.use_opensearch and self.runs_app() and not self.update_config \
                and (self.base_dir / self.config_file).exists():
            declined.append(self.config_file)
        if not self.update_env and (self.base_dir / self.env_file).exists():
            declined.append(self.env_file)
        if not declined:
            return True
        self.print_error(f"The new OpenSearch password would not be written to "
                         f"{' or '.join(declined)}, which would leave the files that hold it "
                         f"disagreeing, so it is not changed. Run setup again and update both "
                         f"files to change it.")
        self.opensearch_admin_password = previous
        if previous.strip() == DEFAULT_OPENSEARCH_PASSWORD:
            self.print_error(f"The password stays {DEFAULT_OPENSEARCH_PASSWORD}, which the "
                             "workers and the librarian refuse.")
        return False

    def existing_env_value(self, name: str) -> Optional[str]:
        """A value from the .env a previous run wrote, or None"""
        target_env = self.base_dir / self.env_file
        if not target_env.exists():
            return None
        with open(target_env, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith(name + "="):
                    return line[len(name) + 1:]
        return None

    def setup_opensearch_password(self):
        """Set up the OpenSearch admin password"""
        self.print_step("OpenSearch Admin Password Configuration")
        runs_opensearch = "opensearch" in self.components

        # A rerun should not quietly replace the password a running cluster
        # already uses: OpenSearch reads OPENSEARCH_INITIAL_ADMIN_PASSWORD only
        # when its data volume is new, so a new one here would lock the workers
        # out rather than change anything
        existing = self.existing_password()
        if existing and existing.strip() == DEFAULT_OPENSEARCH_PASSWORD:
            self.print_error(f"The existing .env uses {DEFAULT_OPENSEARCH_PASSWORD}, the password "
                             "TurkeyBite used to ship with. The workers and the librarian now "
                             "refuse to start with it.")
            self.print_info("If this OpenSearch already holds data, setting a new password here "
                            "is not enough: change it in OpenSearch too. See 'Changing the "
                            "OpenSearch admin password' in the README.")
        elif existing:
            if self.prompt_yes_no("Keep the OpenSearch admin password already in .env?", default=True):
                self.opensearch_admin_password = existing
                return

        if runs_opensearch:
            message = ("Enter an OpenSearch admin password, or press Enter to generate one "
                       f"(at least 8 characters with upper and lower case, a digit and one of "
                       f"{OPENSEARCH_PASSWORD_SYMBOLS})")
        else:
            message = "Enter the OpenSearch admin password set on the search node"

        while True:
            password = self.prompt(message)

            if not password:
                if not runs_opensearch:
                    self.print_error("Enter the password the search node's .env sets as "
                                     "OPENSEARCH_INITIAL_ADMIN_PASSWORD.")
                    continue
                self.opensearch_admin_password = generate_opensearch_password()
                self.print_success("Generated an OpenSearch admin password.")
                self.print_info("IMPORTANT: Save this password. It logs in to OpenSearch "
                                "Dashboards as admin, and other nodes need it:")
                print(self.opensearch_admin_password)
                return

            # A password for this node's own OpenSearch has to meet its rules. A
            # search node elsewhere chose its own, so only the default is refused
            problem = None
            if runs_opensearch or password.strip() == DEFAULT_OPENSEARCH_PASSWORD:
                problem = opensearch_password_problem(password)
            if problem:
                self.print_error(problem)
                continue

            # Confirm password
            confirm = self.prompt("Confirm password")
            if password != confirm:
                self.print_error("Passwords do not match.")
                continue

            self.opensearch_admin_password = password
            self.print_success("OpenSearch admin password set successfully.")
            if runs_opensearch:
                self.print_info("OpenSearch also scores the password for strength and will not "
                                "start if it finds it weak.")
            break

    def setup_retention(self):
        """Ask how long OpenSearch keeps TurkeyBite's indices.

        A rerun offers the period already in .env, so pressing Enter keeps it
        rather than putting back the suggestion for a new install.
        """
        self.print_step("Data Retention")
        self.print_info("Every TurkeyBite index holds per-user browsing data. The librarian "
                        "has OpenSearch delete each daily index once it is older than this "
                        "many days. 0 keeps them forever. A shorter period than the one in "
                        "force is only applied once you confirm it; see 'Data retention' in "
                        "the README.")
        offered = DEFAULT_RETENTION_DAYS
        existing = self.existing_env_value("TURKEYBITE_RETENTION_DAYS")
        if existing is not None and not retention_days_problem(existing):
            offered = int(existing.strip())
        while True:
            answer = self.prompt(f"Delete indices older than how many days? "
                                 f"(default: {offered})")
            if not answer.strip():
                self.retention_days = offered
                break
            problem = retention_days_problem(answer)
            if problem:
                self.print_error(problem)
                continue
            self.retention_days = int(answer.strip())
            break
        if self.retention_days == 0:
            self.print_info("Indices will be kept forever. Set TURKEYBITE_RETENTION_DAYS in "
                            ".env to change that.")
        else:
            self.print_success(f"Indices will be deleted {self.retention_days} days after "
                               "they are created.")

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
        
        # Setup OpenSearch admin password if using OpenSearch, or running it:
        # a node that runs OpenSearch needs an admin password whether or not
        # events are sent to it
        previous_password = self.existing_password()
        if self.use_opensearch or "opensearch" in self.components:
            self.setup_opensearch_password()

        # The librarian is what applies the retention policy
        if self.use_opensearch and "librarian" in self.components:
            self.setup_retention()

        # Setup the main configuration files, both or neither of them getting
        # a new password
        self.decide_updates()
        password_changed = self.keep_password_in_step(previous_password)
        self.setup_config()
        self.setup_env()
        if password_changed:
            self.print_info("The OpenSearch admin password changed in this setup. If OpenSearch "
                            "already holds data it still has the old one, since it reads "
                            "OPENSEARCH_INITIAL_ADMIN_PASSWORD only when its data volume is "
                            "new: change it in OpenSearch too, as 'Changing the OpenSearch admin "
                            "password' in the README describes, then recreate the containers.")
        
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
