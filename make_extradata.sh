#!/bin/bash

SIGNER="4d09853f86263e9050247d9417e6c9e56cdedcf0"

# 32 bytes zero
P1=$(printf "%064d" 0)

# signer (40 chars)
P2="$SIGNER"

# 65 bytes zero (130 chars)
P3=$(printf "%0130d" 0)

echo "0x${P1}${P2}${P3}"
