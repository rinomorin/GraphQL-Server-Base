#!/bin/bash
thisdir="$(dirname "$(readlink -f "$0")")"

# Always run from the directory where this script lives
cd "$thisdir"


# # Activate Python 3.11 environment and restart backend
# source "$thisdir/venv311/bin/activate"
# pkill -f run.py
# python graphql-base/server/run.py &

# # Activate Python 3.12 environment and restart backend
# source "$thisdir/venv312/bin/activate"
# pkill -f run.py
# python graphql-base/server/run.py &
    thisdir="$(dirname "$(readlink -f "$0")")"
    # Start frontend threads
    cd $thisdir/graphql-base/front-end-311
    npm init -y
    $thisdir/graphql-base/front-end-311/start.sh &
    cd $thisdir/graphql-base/front-end-312
    npm init -y
    $thisdir/graphql-base/front-end-312/start.sh &