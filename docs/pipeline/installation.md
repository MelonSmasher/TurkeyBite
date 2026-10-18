# Installation

## Prerequisites

*   Docker and Docker Compose installed on your host system
*   Git to clone the repository

## Installing

1.  **Clone the repository**

    ```bash
    git clone https://github.com/MelonSmasher/TurkeyBite.git
    cd TurkeyBite
    ```

2.  **Initialize the project**

    Run the setup script to create required directories and configuration files:

    ```bash
    bash setup.sh
    ```

    The setup script will guide you through configuration options including:

    -   Deployment type (Development, Small Scale, or Full Scale)
    -   DNS lookup configuration for client IPs
    -   Output options (OpenSearch and/or Syslog)
    -   Service passwords and connection settings. Press Enter at the OpenSearch admin password prompt to have one generated; `Changeit12345!`, the password TurkeyBite used to ship with, is refused

    For distributed deployments, you'll run this script on each node with the appropriate configuration.

    Running it again on an existing install edits `config.yaml` and `.env` rather than replacing them, if you let it update them: it changes only what it asks about, adds settings that are missing, and keeps everything else you set, such as `processor.privacy`, a host's `verify_certs` and `ca_certs`, or `OPENSEARCH_CA_CERT`. Comments in `config.yaml` are not kept. It offers the retention period and OpenSearch password already in `.env`, so pressing Enter keeps them. A new OpenSearch password is written to both files or, if you decline to update either, to neither.

3.  **Review configuration (optional)**

    The setup script automatically generates the following configuration files:

    -   `.env` - Environment variables for Docker containers
    -   `config.yaml` - TurkeyBite application configuration
    -   `docker-compose.yml` - Container orchestration configuration

    While the setup script configures these files based on your selections, you can review and adjust them if needed:

    **Environment Variables** in `.env`:

    ```bash
    # Key environment variables (automatically configured by setup)
    OPENSEARCH_INITIAL_ADMIN_PASSWORD=******      # Password for OpenSearch admin
    OPENSEARCH_PASSWORD=******                    # The same password, for the librarian
    bootstrap.memory_lock=true                     # Enable memory locking for OpenSearch
    node.name=${OPENSEARCH_HOST}                  # Set node name to match host
    discovery.type=single-node                    # Run in single node mode
    OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m        # Configure Java memory limits
    VALKEY_HOST=valkey                            # Valkey/Redis hostname or IP
    VALKEY_PORT=6379                             # Valkey/Redis port
    OPENSEARCH_PORT=9200                         # OpenSearch API port
    BIND9_IP=172.172.0.100                       # Static IP for Bind9 in Docker network
    TURKEYBITE_WORKER_PROCS=2                    # Number of worker processes
    TURKEYBITE_HOSTS_INTERVAL_MIN=720            # Host list refresh interval (minutes)
    TURKEYBITE_IGNORELIST_INTERVAL_MIN=5         # Ignorelist refresh interval (minutes)
    TURKEYBITE_RETENTION_DAYS=90                 # Days before OpenSearch deletes an index, 0 keeps them
    ```

    **Application Configuration** in `config.yaml`:

    ```yaml
    redis:
      host: valkey
      port: 6379
      password: your_password_from_secrets
      db: 0
      host_list_db: 1
      channel: turkeybite
    # ... other configuration sections
    ```

4.  **Secrets Setup**

    The setup script automatically creates the required password files in the `vols/secrets/` directory. These include:

    -   `valkey_password.txt` - Password for Valkey/Redis authentication

    You can review and modify these secrets if needed.

    **Important for Distributed Setups:** When Valkey runs on a dedicated node, copy `valkey_password.txt` from that server to every worker and librarian node. Setup prompts for this password on nodes without local Valkey.

5.  **Configure Bind9 (if using as DNS server)**

    The setup script copies example Bind9 configuration files to the `vols/bind/` directory. Review and modify these files:

    *   `named.conf.local` - Local DNS configuration
    *   `named.conf.options` - DNS server options
    *   `slave.conf` - Zone configurations for slave DNS setup

    For more information on Bind9 configuration see [docs/bind9.md](../bind9.md).

## Running it

1.  **Start the containers**

    ```bash
    docker compose up -d
    ```

2.  **Verify containers are running**

    ```bash
    docker compose ps
    ```

3.  **Access the TurkeyBite Console**

    Deploy it separately as described in [console/README.md](../console/deploying.md). It connects to OpenSearch with a read-only account; OpenSearch Dashboards is no longer deployed. Put TLS in front of the console and use the configured bootstrap account to sign in.
