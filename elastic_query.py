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

#starttime = '2018-09-17T00:28:18.097Z'
#endtime = '2018-09-17T23:54:18.097Z'

start = datetime.strptime(starttime, '%Y-%m-%dT%H:%M:%S.%fZ')
end = datetime.strptime(endtime, '%Y-%m-%dT%H:%M:%S.%fZ')
start = start.replace(tzinfo=to_zone)
end = end.replace(tzinfo=to_zone)


es = Elasticsearch([{'host': ip, 'port': port}])
score = 0
susplocations = ['windows\\temp','windows\\system32','appdata','temp','startup']
suspports = ['4444']
suspreg = ['run','runonce']
susprocs = ['cmd','python','powershell']
suspuser=['SYSTEM']

def checkuser(hit):
	suspusers = []
	global score
	if suspuser[0] in hit['_source']['user']['name']:
		score += 1
		suspusers.append(hit['_source'])
	return suspusers

def checkprocs(hit):
	suspusers = []
	global score
	for proc in susprocs:	
		if proc in hit['_source']['event_data']['Image']:
			score = score + 1
			suspusers.append(hit['_source']['event_data']['Image'])
	return suspusers

def checklocations(hit):
	suspusers = []
	global score
	for proc in susplocations:	
		if proc in hit['_source']['event_data']['TargetObject']:
			score = score + 1
			suspusers.append(hit['_source']['event_data']['TargetObject'])
	return suspusers

def checkregistry(hit):
	suspusers = []
	global score
	for proc in susplocations:	
		if proc in hit['_source']['event_data']['Image']:
			score = score + 1
			suspusers.append(hit['_source']['event_data']['Image'])
	return suspusers

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
		'''
		if not ((sta < dtime) and (dtime < en)):
			a['hits']['hits'].remove(hit)
		else:
			hit['_source']['@timestamp'] = str(dtime)
		'''
	return a


def toepochmilis(time):
    dtime = time.strftime('%s')
    epoch = int(dtime)*1000
    return epoch


def equery(indexname, eventid):
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


# network filter
results = equery(indexname, 3)
outresults('network.json', results)

# Processes Created
results = equery(indexname, 1)
outresults('file.json', results)

# registry add\delete
results = equery(indexname, 12)
outresults('registry-created.json', results)

filtered = filtertime(start, end, results)
bu = []
bp =[]
bl = []
for event in filtered['hits']['hits']:
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

# registry modification
results = equery(indexname, 13)
outresults('registry-edited.json', results)

filtered = filtertime(start, end, results)
bu = []
bg =[]
bl = []
for event in filtered['hits']['hits']:
	try:
		badusers = checkuser(event)
		badlocations = checklocations(event)
		badreg=checkregistry(event)
		bu.extend(badusers)
		bl.extend(badlocations)
		bg.extend(badreg)
	except Exception as e: print(e)

regb={"baduser":bu,"badreg":bg,"badloc":bl}
with open('registry-behavior.json', 'w') as outfile:
    json.dump(regb, outfile)

# file creation
results = equery(indexname, 11)
outresults('file_creation.json', results)

filtered = filtertime(start, end, results)

