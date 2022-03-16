#!/bin/bash

cd ..
docker build --rm -f build_scripts_Docker/Dockerfile_palyanytsya -t ghcr.io/pocket-sunflower/palyanytsya:latest .
docker build --rm -f build_scripts_Docker/Dockerfile_pyrizhok -t ghcr.io/pocket-sunflower/pyrizhok:latest .
