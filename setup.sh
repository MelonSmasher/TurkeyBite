#!/bin/bash

# This script runs the setup_new.py in a Python container

# Get the absolute path to the project directory
PROJECT_DIR=$(pwd)

# Run the setup script in a Python container
docker run --rm -it \
  -v "$PROJECT_DIR:/app" \
  -w /app \
  python:3-alpine \
  sh -c "pip install pyyaml && python setup.py"
