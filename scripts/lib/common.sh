#!/usr/bin/env bash
# Common utilities for Gorape scripts

# Color utilities
info()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
success(){ echo -e "\033[1;32m[DONE]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()   { echo -e "\033[1;31m[ERR ]\033[0m $*" >&2; }
