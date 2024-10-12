## IBM QRADAR SIEM x IBM SOAR Integration Python APP ##

### Provides a QRADAR offense creation mechanism to IBM SOAR with automated incident creating by pulling offenses from IBM QRADAR SIEM and uploading them to IBM SOAR. ###

This program can also be adapted to integrate with other third party systems.

The program contains 2 main threads:

- Thread 1: creates offenses in SOAR. The "last_escalated_offense_offset_id" file contains the last processed offense ID that was created on IBM SOAR.

- Thread 2: tries reuploading failed uploaded offenses to SOAR. The "failed_soar_offense_creations" file contains the failed offenses (offense IDs) that were not uploaded to SOAR. This file will be used by the second thread to retry reuploading them to SOAR.

Each of the threads can also be run individually from each file. If one of the threads fails, the other one will still run if its running.

Logs can be seen on the "logs" folder for each thread separately. The main App thread (app bootstraping or initialization) will be on the app_bootstrap.log
Please, configure the required inputs on the config file (config.ini) before running the script (URL, API keys, file locations... etc).