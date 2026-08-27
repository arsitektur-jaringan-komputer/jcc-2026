#!/bin/bash

docker image rm warmup
docker build . -t warmup
