#!/usr/bin/env python
# this script needs to be run from the /web folder. all refrences below are based on that

import socket
import os
import sys
import time
import errno
from shutil import copyfile
from shutil import copytree
from datetime import datetime
from elasticsearch import Elasticsearch
import json
import conf

virus_path = sys.argv[1]

conf.readconf()
ip = conf.settings.ip
port = int(conf.settings.port)
folder = conf.settings.folder
webfolder = conf.settings.webfolder

es = Elasticsearch([{'host': ip, 'port': port}])
base_folder = folder + "tasks/"

# getting the last analysis id
results = es.search(
    index='static_analysis',
    doc_type='doc',
	size = 1,
    body = {
			  "query": {
				"match_all": {}
			  },
			  "size": 1,
			  "sort": [
				{
				  "timestamp": {
					"order": "desc"
				  }
				}
			  ]
			}
)

print results['hits']['hits'][0]['_id']
latest = int(results['hits']['hits'][0]['_id']) + 1
print('Task id: '+ `latest`)
# creating a folder for all the results
try:
	task_folder = base_folder + `latest`
	os.makedirs(task_folder)
except OSError as e:
	if e.errno != errno.EEXIST:
		raise
try:
	task_screen_folder = task_folder + "/screenshots/"
	os.makedirs(task_screen_folder)
except OSError as e:
	if e.errno != errno.EEXIST:
		raise

# copy neccesary files to the task folder: try.html, dataTables.js, elasticquery, satic analysis
# TODO: is it neccesary to mantion the name of he file in the end of the path?
# TODO: is it not possible to just copy all the folder instead all the files......?
shutil.copytree(src, dst, symlinks=False, ignore=None)
shutil.copytree(webfolder, task_folder)

# os.makedirs(task_folder+"/js")
# copyfile(webfolder+"js/dataTables.js",task_folder + "/js/dataTables.js")
# copyfile(webfolder+"js/tabs.js",task_folder + "/js/tabs.js")
# copyfile(webfolder+"elastic_query.py",task_folder + "/elastic_query.py")
# copyfile(webfolder+"static_analysis.py",task_folder + "/static_analysis.py")
# copyfile(webfolder+"tcp_server.py",task_folder + "/tcp_server.py")
# copyfile(webfolder+"conf.py",task_folder + "/conf.py")
# copyfile(webfolder+"puckoo.conf",task_folder + "/puckoo.conf")
# os.makedirs(task_folder+"/style")
# copyfile(webfolder+"style/beautiful_tabs.css",task_folder + "/style/beautiful_tabs.css")
# copyfile(webfolder+"style/stylesheet.css",task_folder + "/style/stylesheet.css")
# copyfile(webfolder+"style/screenshots.css",task_folder + "/style/screenshots.css")
# os.makedirs(task_folder+"/graphics")
# copyfile(webfolder+"graphics/sand.jpeg",task_folder + "/graphics/sand.jpeg")
# copyfile(webfolder+"index.php",task_folder + "/index.php")
# copyfile(webfolder+"dispimages.php",task_folder + "/dispimages.php")
# copyfile(webfolder+"printIAT.php",task_folder + "/printIAT.php")
# copyfile(webfolder+"head.php",task_folder + "/head.php")
# copyfile(webfolder+"header.php",task_folder + "/header.php")

#change current working directory to the task folder
os.chdir(task_folder)

# run the static analysis first
#input argument: path to virus + taskid
print "Starting static analysis..."
os.system("python static_analysis.py " + virus_path + " " + `latest`)
# now we will run the scripts with the suitable arguments: staticanalysis: which index to query from, 
starttime = datetime.now()
#starttime= datetime.strptime('2017-12-06T15:44:18.097Z','%Y-%m-%dT%H:%M:%S.%fZ')
os.system("python tcp_server.py " + virus_path + " " + task_folder) #tcpserver: recives path as argument 
#wait for it to finish (return code 0?)
# TODO: adujst the time settings
# TODO: change the sleep method
time.sleep(100)
endtime = datetime.now()

indexyear = starttime.year
indexmonth = starttime.month
indexday = starttime.day

if int(indexday) < 10:
	indexday = ('0'+`indexday`)

if int(indexmonth) < 10:
	indexmonth = ('0'+`indexmonth`)

indexname = 'winlogbeat-6.0.0-{0}.{1}.{2}'.format(indexyear,indexmonth,indexday)
#elasticquery.py :
#input: index name + taskid + 
print "Querying elasticsearch and preparing report files."
#print str(starttime), str(endtime)
starttime = str(starttime).replace(" ","T")[:-3]+"Z"
#starttime = '2017-12-06T10:04:18.097Z'
endtime = str(endtime).replace(" ","T")[:-3]+"Z"
#endtime = '2017-12-06T16:24:18.097Z'

os.system("python elastic_query.py " + indexname + " " + starttime + " " + endtime)
html_file = task_folder + "/index.php"
os.system("firefox -new-tab -url http://"+ip+"/tasks/" + `latest` + "/index.php" )

#TODO insert fog api here to revert the machine to clean snapshot. or maybe better when notifiers gets a new file
#TODO make it possible to run several analyses at once.

