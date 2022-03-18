#!/bin/bash

cd ..
pwd
docker build -f build_scripts_Docker/Dockerfile_palyanytsya -t ghcr.io/pocket-sunflower/palyanytsya:latest .
docker build -f build_scripts_Docker/Dockerfile_pyrizhok -t ghcr.io/pocket-sunflower/pyrizhok:latest .
