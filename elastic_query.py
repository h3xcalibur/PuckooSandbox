from elasticsearch import Elasticsearch
import json
import sys
from datetime import datetime
from dateutil import tz
from dateutil import parser
import conf
conf.readconf()
ip = conf.settings.ip
port = int(conf.settings.port)
folder = conf.settings.folder

indexname = sys.argv[1]
starttime = sys.argv[2]
endtime = sys.argv[3]

from_zone = tz.tzutc()
to_zone = tz.tzlocal()

starttime = '2018-09-16T00:28:18.097Z'
endtime = '2018-09-16T23:54:18.097Z'

start = datetime.strptime(starttime, '%Y-%m-%dT%H:%M:%S.%fZ')
end = datetime.strptime(endtime, '%Y-%m-%dT%H:%M:%S.%fZ')
start = start.replace(tzinfo=to_zone)
end = end.replace(tzinfo=to_zone)


es = Elasticsearch([{'host': ip, 'port': port}])
score = 0
# TODO: Make the path in the function to lowercase so it wouldnt matter..
susplocations = ['Windows\\temp','Windows\\Temp', 'windows\\temp','Windows\\System32', 'windows\\system32','appdata', 'Appdata','temp', 'Temp','startup', 'Startup']
suspports = ['4444']
suspreg = ['run','runonce', 'Run', 'Runonce', 'RunOnce']
susprocs = ['cmd','python','powershell']
suspuser=['SYSTEM']


# function to check "bad stuff", to be presented in the summary screen of suspicious activity
# TODO: filter out legit operations
def checkuser(hit):
	suspusers = []
	suspevent = {}
	global score
	if suspuser[0] in hit['_source']['user']['name']:
		score += 1
		#suspusers.append(hit['_source'])
		# important info fom alert to be show in the table
		image = hit['_source']['event_data']['Image']
		description = hit['_source']['event_data']['Description']
		pid = hit['_source']['event_data']['ProcessId']
		cmdline = hit['_source']['event_data']['CommandLine']
		suspevent.update({"pid":pid,"image":image,"description":description,"cmdline":cmdline})
		suspusers.append(suspevent)
	return suspusers

def checkprocs(hit):
	suspusers = []
	suspevent = {}
	global score
	for proc in susprocs:	
		if proc in hit['_source']['event_data']['Image']:
			score = score + 1
			#suspusers.append(hit['_source']['event_data']['Image'])
			image = hit['_source']['event_data']['Image']
			description = hit['_source']['event_data']['Description']
			pid = hit['_source']['event_data']['ProcessId']
			cmdline = hit['_source']['event_data']['CommandLine']
			suspevent.update({"pid":pid,"image":image,"description":description,"cmdline":cmdline})
			suspusers.append(suspevent)
	return suspusers

def checklocations(hit):
	suspusers = []
	suspevent = {}
	global score
	for location in susplocations:
		if location in hit['_source']['event_data']['Image']:
			score = score + 1
			#suspusers.append(hit['_source']['event_data']['Image'])
			image = hit['_source']['event_data']['Image']
			description = hit['_source']['event_data']['Description']
			pid = hit['_source']['event_data']['ProcessId']
			cmdline = hit['_source']['event_data']['CommandLine']
			suspevent.update({"pid":pid,"image":image,"description":description,"cmdline":cmdline})
			suspusers.append(suspevent)
	return suspusers

def checkregistry(hit):
	suspusers = []
	suspevent = {}
	global score
	for reg in suspreg:
		try:
			if reg in hit['_source']['event_data']['TargetObject']:
				score = score + 1
				#suspusers.append(hit['_source']['event_data']['TargetObject'])
				image = hit['_source']['event_data']['Image']
				description = hit['_source']['event_data']['TargetObject']
				pid = hit['_source']['event_data']['ProcessId']
				evttype = hit['_source']['event_data']['EventType']
				details = hit['_source']['event_data']['Details']
				suspevent.update({"pid":pid,"image":image,"description":description,"details":details, "evttype":evttype})
				suspusers.append(suspevent)
		except:
			print("no target object field in event data")
	return suspusers

def checkports(hit):
	suspusers = []
	suspevent = {}
	global score
	for port in suspports:
		try:
			if port in hit['_source']['event_data']['DestinationPort']:
				score = score + 1
				image = hit['_source']['event_data']['Image']
				srcip = hit['_source']['event_data']['SourceIp']
				dstip = hit['_source']['event_data']['DestinationIp']
				dstport = hit['_source']['event_data']['DestinationPort']
				pid = hit['_source']['event_data']['ProcessId']
				suspevent.update({"pid":pid,"image":image,"srcip":srcip,"dstip":dstip, "dstport":dstport})
				suspusers.append(suspevent)
		except:
			print("no target object field in event data")
	return suspusers
'''
# Filters events based on start\end times
def filtertime(sta,en,result):
    a = result.copy()
    for hit in a['hits']['hits']:
		e = hit['_source']['@timestamp']
		#e = hit['_source']['event_data']['UtcTime']
		#dtime = datetime.strptime(e, '%Y-%m-%dT%H:%M:%S.%fZ')
		dtime = parser.parse(e)
		dtime = dtime.replace(tzinfo=from_zone)
		dtime = dtime.astimezone(to_zone)
		if ((sta < dtime) and (dtime < en)):
			hit['_source']['@timestamp'] = str(dtime)
		else:
			a['hits']['hits'].remove(hit)
	return a
'''

def toepochmilis(time):
    dtime = time.strftime('%s')
    epoch = int(dtime)*1000
    return epoch


def equery(indexname, eventid):
	# elastic query based on event id
    results = es.search(
        index=indexname,
        doc_type='doc',
        size=500,
        body={
            'query': {
                'bool': {
                    'must': {
                        'match': {'event_id': eventid}
                    }
                }
            }
        }
    )
    return results


def filterequery(indexname, eventid, gtetime, ltetime):
	# filter query based on start\end event time
    results = es.search(
        index=indexname,
        doc_type='doc',
        size=500,
        body={
            'query': {
                'bool': {
                    'must': {
                        'match': {'event_id': eventid}
                    },
                    'filter':{
                        "range": {
                            "@timestamp": {
                                "gte": gtetime,
                                "lte": ltetime
                            }
                        }
                    }
                }
            }
        }
    )
    return results

def outresults(filename, results):
    with open(filename, 'w') as outfile:
        json.dump(results, outfile)


# Processes Created
#results = equery(indexname, 1)
results = filterequery(indexname, 1, starttime, endtime)
outresults('file.json', results)

bu = []
bp =[]
bl = []
for event in results['hits']['hits']:
	try:
		badusers = checkuser(event)
		badprocs = checkprocs(event)
		badlocations = checklocations(event)
		bu.extend(badusers)
		bp.extend(badprocs)
		bl.extend(badlocations)
	except Exception as e: print(e)

procb={"baduser":bu,"badprocess":bp,"badloc":bl}
with open('procs_behavior.json', 'w') as outfile:
    json.dump(procb, outfile)

# network filter
#results = equery(indexname, 3)
results = filterequery(indexname, 3, starttime, endtime)
outresults('network.json', results)

bn = []
for event in results['hits']['hits']:
	try:
		badports = checkprocs(event)
		bn.extend(badports)
	except Exception as e: print(e)

bports={"badports":bn}
with open('network_behavior.json', 'w') as outfile:
    json.dump(bports, outfile)

# file creation
#results = equery(indexname, 11)
results = filterequery(indexname, 11, starttime, endtime)
outresults('file_creation.json', results)

bl = []
for event in results['hits']['hits']:
	try:
		badusers = checkuser(event)
		badprocs = checkprocs(event)
		badlocations = checklocations(event)
		bu.extend(badusers)
		bp.extend(badprocs)
		bl.extend(badlocations)
	except Exception as e: print(e)
procb={"badloc":bl}
with open('files_behavior.json', 'w') as outfile:
    json.dump(procb, outfile)

# registry add\delete
#results = equery(indexname, 12)
results = filterequery(indexname, 12, starttime, endtime)
outresults('registry-created.json', results)
br = []
for event in results['hits']['hits']:
	try:
		badregistry = checkregistry(event)
		br.extend(badregistry)
	except Exception as e: print(e)
procb={"badreg":br}
with open('registry-behavior.json', 'w') as outfile:
    json.dump(procb, outfile)

# registry modification
#results = equery(indexname, 13)
results = filterequery(indexname, 13, starttime, endtime)
outresults('registry-edited.json', results)

br = []
for event in results['hits']['hits']:
	try:
		badregistry = checkregistry(event)
		br.extend(badregistry)
	except Exception as e: print(e)
procb={"badreg":br}
with open('registry-behavior.json', 'w') as outfile:
    json.dump(procb, outfile)
