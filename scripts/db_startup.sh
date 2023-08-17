#!/bin/sh
# Script to download and initialize PostgreSQL.

# The default path for postgres. CHANGE THIS IF ITS NOT THE RIGHT PATH.
MACOS_PSQL_PATH="/opt/homebrew/opt/postgresql@15/bin/"
export LC_ALL="en_US.UTF-8"
DBNAME="ftdb"
SUPERUSER="ftsuperuser"
USER="ftuser"

check_brew_installed() {
    brew --version > /dev/null
    return $?
}

macos_startup() {
    # TODO: Add curl approach
    check_brew_installed || (echo "brew not installed." && exit)
    case $(brew list) in
        *"postgresql@15"*)
            ;;
        *)
            echo "PostgreSQL15 is not installed. Installing ..."
            brew install postgresql@15
            ;;
    esac
    echo "PostgreSQL15 installed"
    export PATH="$MACOS_PSQL_PATH:$PATH"
    echo "Creating database cluster"
    initdb -U $SUPERUSER --pwprompt --locale="en_US.UTF-8" --pgdata="ftdb/ftcluster"
    # start server
    echo "Starting server"
    pg_ctl -D 'ftdb/ftcluster' start
    echo "Creating user"
    createuser -W -U $SUPERUSER $USER
    echo "Creating database"
    createdb -U $SUPERUSER -O $USER $DBNAME
    echo "Created database $DBNAME and $USER as the owner."
}

[ "$(uname -s)" = "Darwin" ] && macos_startup
