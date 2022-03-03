#!/bin/bash

docker login --username pocketsunflower --password "$1"

docker image tag pocketsunflower/palyanytsya:latest pocketsunflower/palyanytsya:latest
docker push pocketsunflower/palyanytsya:latest

docker image tag pocketsunflower/pyrizhok:latest pocketsunflower/pyrizhok:latest
docker push pocketsunflower/pyrizhok:latest
