# The Sports Catalog
A web app written in Python/Flask that shows a catalog of sports equipment. Logged in users can create categories and items.

## Dependencies
Python
SQLAlchemy
Flask

## How to Run
1) Clone the repo.
2) Run application.py. This can be done from the command line, `python application.py`.
3) Navigate to `http://localhost:8000` in any web browser.

## Generate the default database
First you must delete the catalog.db file. Then, you must run 'python database_setup.py' and then 'python categories.py'. This will generate the default catalog of sports equipment. 