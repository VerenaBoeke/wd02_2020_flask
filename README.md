# WD02 2020 Flask
Web Development 2 - Heroku Flask Server

# wd2 2020 10 Flask
Web Development 2 - Heroku Flask Server
## how to use flask migrate
- make sure that FLASK_APP environment variable is set
  - Unix: `export FLASK_APP=`pwd`/main.py`
  - Windows: `set FLASK_APP=%cd%\main.py`
 
- remove the database
- if using flask migrate the first time, initialize it: `flask db init`. this will create a folder called *migration* in the project with all migration commands
- after each change, migrate: `flask db migrate -m "<change description>"`
- run upgrade from the migration, this is how to upgrade on the server based on alembic versions folder: `flask db upgrade`
- additionally, test locally first, and adjust update steps in upgrade scripts if necessary
## add release tasks
- create release_tasks.sh
- update Procfile to have a release phase: `release: ./release-tasks.sh`
- update release tasks permissions:
  - `git update-index --chmod=+x release-tasks.sh`