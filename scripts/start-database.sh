#!/bin/bash

docker run --name db -d -it \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=postgres \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    -e POSTGRES_DB=unsubtle \
    -p 5432:5432 \
    postgres
