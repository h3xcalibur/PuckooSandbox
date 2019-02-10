# Source code by Dana Iosifovich 2017
import os
import hashlib
import magic
import string
import re
from elasticsearch import Elasticsearch
import json
from datetime import datetime
import time
import requests
import sys

# new!
import pefile
from pprint import pprint
import conf
conf.readconf()
ip = conf.settings.ip
port = int(conf.settings.port)
folder = conf.settings.folder
webfolder = conf.settings.webfolder

es = Elasticsearch([{'host': ip, 'port': port}])
BLOCKSIZE = 65536

class FileAnalysis:
    def __init__(self, file_path):
        self.file_path = file_path
        # self.sha256 = self.calc_hash("sha256")
        # self.shamd5 = self.calc_hash("md5")
        # self.shasha1 = self.calc_hash("sha1")
        self.sha256 = self.calc_sha256()
        self.md5 = self.calc_md5()
        self.sha1 = self.calc_sha1()
        self.file_type = self.get_file_type()
        self.size = self.get_file_size()


    def get_file_type(self):
        filetype = magic.from_file(self.file_path, mime=True)
        return filetype

    def ext_match_type(self):
        """Checks if file's extension matches its type"""
        extension = os.path.splitext(self.file_path)[1][1:]
        ftype = self.get_file_type()
        if extension in ftype:
            return True
        else:
            return False

    def get_file_size(self):
        """returns file size in KBs"""
        size = (os.path.getsize(self.file_path)) / 1024.0
        return size


    def calc_sha256(self):
        hasher = hashlib.sha256()
        with open(self.file_path, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        return hasher.hexdigest()

    def calc_md5(self):
        hasher = hashlib.md5()
        with open(self.file_path, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        return hasher.hexdigest()

    def calc_sha1(self):
        hasher = hashlib.sha1()
        with open(self.file_path, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        return hasher.hexdigest()

    def strings(self):
        """extracts strings of the binary file"""
        stringsr = os.system("strings " + self.file_path + ">> strings.txt")
        return stringsr

#extracts import address table
    def getIAT(self):
        pe = pefile.PE(self.file_path, fast_load=False)
        IAT = {}
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            IAT[entry.dll] = []
            for imp in entry.imports:
                IAT[entry.dll].append(imp.name)
		return IAT

    def find_urls(self):
		with open("strings.txt", 'rb') as afile:
			strings = afile.readlines()
		urls = []
		for f_string in strings:
			urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', f_string)
			return urls

    def find_cnc(self):
		with open("strings.txt", 'rb') as afile:
			strings = afile.read()
		cnc_calls = []
		for a_string in strings:
			if "rcv" or "send" or "exec" in a_string:
                # TODO: work on it to be less dumb + return the contect and not the whole string
				cnc_calls.append(a_string)
		return cnc_calls

filepath = sys.argv[1]
indexid = sys.argv[2]
fa = FileAnalysis(filepath)
filestings=fa.strings()
urls = fa.find_urls()
list(urls) # TODO: wtf? do something with this
cncs= fa.find_cnc()
ba = fa.ext_match_type()
print ba

# query virustotal
# TODO: replace the hardcoded api key with the conf file
params = {'apikey': 'a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088', 'resource': fa.sha256}
headers = {"Accept-Encoding": "gzip, deflate","User-Agent" : "gzip,  My Python requests library example client or username"}
response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
json_response = response.json()
positives = json_response['positives']
totalscans= json_response['total']
# specific AV detenctions 
detectedbysymantec =  json_response['scans']['Symantec']['detected']
detectedbymcafee =  json_response['scans']['McAfee']['detected']
detectedbymicrosoft =  json_response['scans']['Microsoft']['detected']

results = {"sha256":fa.sha256,"md5":fa.md5,"sha1":fa.sha1,"size":fa.size,"matches_file_type":fa.ext_match_type(),
           "file_type":fa.get_file_type(),"detectedbysymantec":detectedbysymantec,"detectedbymcafee":detectedbymcafee,
           "detectedbymicrosoft":detectedbymicrosoft,"virustotal":totalscans,"baddetections":positives}
print results
print "Indexing static analysis into elasticsearch"
es.index(index="static_analysis", doc_type="doc", id=indexid, body={"data":str(results), "timestamp": datetime.now()})
arr = []
arr.append(results)
#resultst = es.search(
#    index='my-index',
#    doc_type='doc',
#	size = 100,
#    body={
#      'query': {
#        'bool': {
#          'must': {
#            'match': {'_id': x}
#          }        }      }    })
print "Writing static analysis results to file"
with open('static.json', 'w') as outfile:
    json.dump(arr, outfile)

iattofile = fa.getIAT()
with open('import_table.json', 'wt') as out:
    pprint(iattofile, stream=out)