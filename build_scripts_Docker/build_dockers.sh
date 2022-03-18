#!/bin/bash

# make project root foolder our working path
SCRIPT_PARENT_PATH=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd "$SCRIPT_PARENT_PATH/.."

# build the containers
#docker build -f build_scripts_Docker/Dockerfile_palyanytsya -t ghcr.io/pocket-sunflower/palyanytsya:latest .
docker build -f build_scripts_Docker/Dockerfile_pyrizhok -t ghcr.io/pocket-sunflower/pyrizhok:latest .
