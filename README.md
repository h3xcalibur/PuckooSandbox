# PuckooSandbox
Sandbox written in python, html and friends. Based on Sysmon events, winlogbeat that collects them and elasticsearch that stores them. Provides comfortable view of everything that happened on the victim system (registry, files, processes, network).

Written for a university project, built from scratch - had my share of fun of dealing with html\css\javascript\php.
The sandbox interacts with a victim vritualbox machine, python scripts for tcp server\client communication and screengrabbing.
The virtual machine has preinstalled Sysmon for logging system activites (no process injection involved), and WinLogBeat for collecting the logs to an Elasticsearch server.

All of the information can be viewed in a comfortable way at the website: static analysis (hashes, import table, VT results), dynamic analysis (all logs of registry activities, added files, created processes and network communication).

### Examples:
**Network view** showing time, process who initiated the communication, src ip, dst ip and dst port
![network analysis](https://raw.githubusercontent.com/h3xcalibur/PuckooSandbox/master/screenshots/7.png)

**Static analysis** of shows hashes, size of file and file type. Also, a big button at the buttom to show import address table.
![static analysis](https://raw.githubusercontent.com/h3xcalibur/PuckooSandbox/master/screenshots/8.jpeg)

Also, **screenshots** from the victim machine are collected and presented as follows:
![screenshotsview](https://raw.githubusercontent.com/h3xcalibur/PuckooSandbox/master/screenshots/1.png)

**Dynamic analysis**
Shows added\deleted registry keys, modified registry keys, created processes and created files on the system during the analysis.
Each category is separated with tabs. In the created processes tab we can see information about the **proceeses that were created**: when, who is the parent process and what command line it used, pid, path to process, command line, user who created it and hashes of the process.
![dynamic analysis createdprocs](https://raw.githubusercontent.com/h3xcalibur/PuckooSandbox/master/screenshots/5.png)

Registry set operations:
![dynamic analysis regset](https://raw.githubusercontent.com/h3xcalibur/PuckooSandbox/master/screenshots/4.png)

Registry keys creation:
![dynamic analysis regadd](https://raw.githubusercontent.com/h3xcalibur/PuckooSandbox/master/screenshots/6.png)

Dropped files:
![dynamic analysis files](https://raw.githubusercontent.com/h3xcalibur/PuckooSandbox/master/screenshots/2.png)
