#!/bin/bash

if [ -e "main" ]; then
  echo "deleting main..."
  rm main
fi

if [ -e "obs" ]; then
  echo "deleting obs..."
  rm obs
fi

gcc -o obs main.c paillier_wbsm2_obs.c -lrelic_s && ./obs
gcc -o main paillier_wbsm2.c -lrelic_s && ./main
