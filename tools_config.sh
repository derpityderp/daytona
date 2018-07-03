#!/usr/bin/env bash
# shellcheck disable=SC2034
set -eu -o pipefail

# REQUIRED; uncomment and set this to match your project name.
# This should almost always be the github repo name.
NAME=daytona

# Required; git tag of sre-tools to use for scripts
SRE_TOOLS_VERSION=0.8.0
