#!/usr/bin/env bash
# shellcheck disable=SC2034
set -eu -o pipefail

# REQUIRED; uncomment and set this to match your project name.
# This should almost always be the github repo name.
NAME=daytona

# Required; git tag of sre-tools to use for scripts
SRE_TOOLS_VERSION=0.11.1

# Example: use ECR instead of Quay
# DOCKER_REGISTRY=433745872707.dkr.ecr.us-west-2.amazonaws.com

# Example: supply extra args to helm during deploy; space-delimited output.
# Note that you don't normally need to do this unless you need image info passed into the
# chart at non-standard paths; these values are supplied at image.* by default.
#
# function extra_helm_args {
#     ARGS=(
#         --set "celery.image.repository=$DOCKER_REPO"
#         --set "celery.image.tag=$DOCKER_TAG"
#         --set "celery.image.pullPolicy=$PULL_POLICY"
#     )
#     echo "${ARGS[@]}"
# }
