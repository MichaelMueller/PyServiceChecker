# PyServiceChecker
A cross platform Service Checker written in python.
This script checks tcp connections for services that are defined in some config file.

## Setup
 - Create a file "PyServiceCheckerConfig.json" from the sample file "PyServiceCheckerConfig.sample.json"
 - Cd to the current project directory and call "python src/PyServiceChecker.py".
 - The script will iterate through your service definitions and check whether the service is up and running on its tcp port or not
 - If the status changed (online > offline, offline > online), it will send an e-mail as defined in the config
 - Create a cron job if you want to