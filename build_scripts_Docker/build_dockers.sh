#!/bin/bash

cd ..
docker build --rm -f build_scripts_Docker/Dockerfile_palyanytsya -t pocketsunflower/palyanytsya:latest .
docker build --rm -f build_scripts_Docker/Dockerfile_pyrizhok -t pocketsunflower/pyrizhok:latest .
