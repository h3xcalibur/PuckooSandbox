# PuckooSandbox
Sandbox written in python, html and friends. Based on Sysmon events, winlogbeat that collects them and elasticsearch that stores them. Provides comfortable view of everything that happened on the victim system (registry, files, processes, network).

Written for a university project, built from scratch - had my share of fun of dealing with html\css\javascript\php.
The sandbox interacts with a victim vritualbox machine, python scripts for tcp server\client communication and screengrabbing.
The virtual machine has preinstalled Sysmon for logging system activites (no process injection involved), and WinLogBeat for collecting the logs to an Elasticsearch server.

All of the information can be viewed in a comfortable way at the website: static analysis (hashes, import table, VT results), dynamic analysis (all logs of registry activities, added files, created processes and network communication).
