#!/bin/bash

# prompt function
prompt() {
    read -p "$1 "
}

# function to generate a random password for valkey_password
valkey_password() {
    # generate a 128 character random password
    python3 -c 'import secrets; print(secrets.token_urlsafe(128))'
}

# check for a .env file
if [ ! -f .env ]; then
    echo "env file not found, copying example"
    cp src/support/example.env .env
else
    echo "env file found"
    prompt "Do you want to overwrite the env file? (y/n)"
    if [ "$REPLY" = "y" ]; then
        cp src/support/example.env .env
    fi
fi

# check for a docker-compose.yml file
if [ ! -f docker-compose.yml ]; then
    echo "docker-compose.yml file not found, copying example"
    cp src/support/docker-compose.example.yml docker-compose.yml
else
    echo "docker-compose.yml file found"
    prompt "Do you want to overwrite the docker-compose.yml file? (y/n)"
    if [ "$REPLY" = "y" ]; then
        cp src/support/docker-compose.example.yml docker-compose.yml
    fi
fi

# check for a config.yaml file
if [ ! -f config.yaml ]; then
    echo "config.yaml file not found, copying example"
    cp src/support/config.example.yaml config.yaml
else
    echo "config.yaml file found"
    prompt "Do you want to overwrite the config.yaml file? (y/n)"
    if [ "$REPLY" = "y" ]; then
        cp src/support/config.example.yaml config.yaml
    fi
fi

# check for the valkey_password secret
if [ ! -f vols/secrets/valkey_password.txt ]; then
    echo "valkey_password secret not found, generating one"
    valkey_password > vols/secrets/valkey_password.txt
else
    echo "valkey_password secret found"
    prompt "Do you want to overwrite the valkey_password secret? (y/n)"
    if [ "$REPLY" = "y" ]; then
        valkey_password > vols/secrets/valkey_password.txt
    fi
fi

echo "Setup complete"
echo "Edit the .env file to set the environment variables"
echo "Edit config.yaml to set the configuration options"
echo "Run docker-compose up -d to start the containers"
