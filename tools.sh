#!/usr/bin/env bash
set -eu -o pipefail

#####################################
### This file is maintained at:
### https://github.robot.car/cruise/sre-tools/blob/master/client_scripts/tools.sh
### Don't make changes in client project repos; they will be overwritten.
#####################################

# shellcheck disable=SC1091
. tools_config.sh

# Set this during development to ignore SRE_TOOLS_VERSION and use your local checkout 
# under $USE_LOCAL, e.g. if you have ~/sre-tools then: USE_LOCAL=~ ./tools.sh ...
USE_LOCAL=${USE_LOCAL:-""}

# Avoid polluting stdout in case using a script that provides output
function log {
    echo "$@" >&2
}

NAME=${NAME:-""}
if [[ ! $NAME ]]; then
    log "Must set project NAME in tools_config.sh"
    exit 1
fi

TOOLS_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # Get absolute path
if [[ $TOOLS_SH_DIR != $(pwd) ]]; then
    log "ERROR: You must run tools.sh from the project root, which should be where tools.sh is located."
    exit 1
fi
if [[ $(basename "$TOOLS_SH_DIR") != "$NAME" ]]; then
    log "WARNING: Configured NAME ($NAME) does not match current directory name ($TOOLS_SH_DIR)."
fi

if [[ $USE_LOCAL ]]; then
    CACHE_DIR=$USE_LOCAL
    log "Using local $CACHE_DIR/sre-tools"
else
    CACHE_DIR=.cache

    (
        mkdir -p $CACHE_DIR
        cd $CACHE_DIR
        if [[ ! -d sre-tools ]]; then
            git clone -q git@github.robot.car:cruise/sre-tools
        fi
        cd sre-tools
        git fetch -q --all
        git checkout -q "$SRE_TOOLS_VERSION"
        log "sre-tools at $(git log --oneline --decorate | head -n 1)"
    )
fi

# shasum is available in both CI and default OS X env
EXPECTED_HASH=$(shasum $CACHE_DIR/sre-tools/client_scripts/tools.sh)
GOT_HASH=$(shasum tools.sh)
# Filter out filename after hashes with %% replacement
if [[ "${GOT_HASH%% *}" != "${EXPECTED_HASH%% *}" ]];then
    cp $CACHE_DIR/sre-tools/client_scripts/tools.sh tools.sh
    log "tools.sh has been upgraded; please try again. If you're getting this error in CI, run tools.sh locally" \
         "and check the upgraded tools.sh into git."
    exit 1
fi

if [[ $# -lt 1 ]]; then
    log "Usage: ./tools.sh <command>"
    exit 1
fi

CMD=$1
shift

# shellcheck disable=SC1090
. "$CACHE_DIR/sre-tools/$CMD.sh"
