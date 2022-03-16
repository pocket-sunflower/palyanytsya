#!/bin/bash

docker login ghcr.io --username "pocket-sunflower" --password "$1"

docker push ghcr.io/pocket-sunflower/palyanytsya:latest

docker push ghcr.io/pocket-sunflower/pyrizhok:latest
