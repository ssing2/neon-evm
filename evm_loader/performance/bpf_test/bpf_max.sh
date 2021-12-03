#! /bin/bash -p
#
# the test sends MaxBpfInstruction instructions in tranactions
# Each transaction contains 143 instructions
# 
# it is necessary to set EVM_LOADER and SOLANA_URL environment variables
#
# args:
#   $1 - count of processes
#
# example:
# ./bpf_max.sh 10 


if [ ${#EVM_LOADER} -eq 0 ]; then
  echo  "EVM_LOADER is not deployed"
  exit 1
fi

if [ ${#SOLANA_URL} -eq 0 ]; then
  echo  "SOLANA_URL is not defined"
  exit 1
fi

echo EVM_LOADER $EVM_LOADER
echo SOLANA_URL $SOLANA_URL
echo -e '\nCOUNT OF PROCESSES' $1


parallel --jobs 0 --keep-order --results log.bpf_max python3 bpf_max.py --postfix {}   :::  $(seq $1)
