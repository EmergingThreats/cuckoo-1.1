# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import subprocess
import re
import json
import sys
import urllib2
import urllib
import time
import socket
import struct
import copy

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report 

log = logging.getLogger(__name__)

class Moloch(Report):

    """Moloch processing."""
    def cmd_wrapper(self,cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout,stderr = p.communicate()
        return (p.returncode, stdout, stderr)
    
    # This was useful http://blog.alejandronolla.com/2013/04/06/moloch-capturing-and-indexing-network-traffic-in-realtime/
    def update_tags(self,tags,expression):
        auth_handler = urllib2.HTTPDigestAuthHandler()
        auth_handler.add_password(self.MOLOCH_REALM, self.MOLOCH_URL, self.MOLOCH_USER, self.MOLOCH_PASSWORD)
        opener = urllib2.build_opener(auth_handler)
        data = urllib.urlencode({'tags' : tags})
        qstring = urllib.urlencode({'date' : "-1",'expression' : expression})
        TAG_URL = self.MOLOCH_URL + 'addTags?' + qstring
        try:
            response = opener.open(TAG_URL,data=data)
            if response.code == 200:
                plain_answer = response.read()
                json_data = json.loads(plain_answer)
            time.sleep(.5)
        except Exception, e:
            raise e

        
    def run(self,results):
        """Run Moloch to import pcap
        @return: nothing 
        """
        self.key = "moloch"
        self.alerthash ={}
        self.fileshash ={}
        self.MOLOCH_CAPTURE_BIN = self.options.get("capture", None)
        self.MOLOCH_CAPTURE_CONF = self.options.get("captureconf",None)
        self.CUCKOO_INSTANCE_TAG = self.options.get("node",None)
        self.MOLOCH_USER = self.options.get("user",None)
        self.MOLOCH_PASSWORD = self.options.get("pass",None) 
        self.MOLOCH_REALM = self.options.get("realm",None)
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.MOLOCH_URL = self.options.get("base",None)

        m = re.search(r"\/(?P<task_id>\d+)\/dump.pcap$",self.pcap_path)
        if m == None:
            log.warning("Unable to find task id from %s" % (self.pcap_path))
            return results  
        else:
            self.task_id = m.group("task_id")

        if not os.path.exists(self.MOLOCH_CAPTURE_BIN):
            log.warning("Unable to Run moloch-capture: BIN File %s Does Not Exist" % (self.MOLOCH_CAPTURE_BIN))
            return
        
        if not os.path.exists(self.MOLOCH_CAPTURE_CONF):
            log.warning("Unable to Run moloch-capture Conf File %s Does Not Exist" % (self.MOLOCH_CAPTURE_CONF))
            return         
        try:
            cmd = "%s -c %s -r %s -n %s -t %s:%s" % (self.MOLOCH_CAPTURE_BIN,self.MOLOCH_CAPTURE_CONF,self.pcap_path,self.CUCKOO_INSTANCE_TAG,self.CUCKOO_INSTANCE_TAG,self.task_id)
        except Exception,e:
            log.warning("Unable to Build Basic Moloch CMD: %s" % e)
             
        if self.task["category"] == "file":
            try:
                if results.has_key('virustotal'):
                    for key in results["virustotal"]["scans"]:
                        if results["virustotal"]["scans"][key]["result"]:
                            cmd = cmd + " -t \"VT:%s:%s\"" % (key,results["virustotal"]["scans"][key]["result"])
            except Exception,e:
                log.warning("Unable to Get VT Results For Moloch: %s" % e)


            if results["target"]["file"].has_key("md5") and results["target"]["file"]["md5"]:
                cmd = cmd + " -t \"md5:%s\"" % (results["target"]["file"]["md5"])
            if results["target"]["file"].has_key("sha1") and results["target"]["file"]["sha1"]:
                cmd = cmd + " -t \"sha1:%s\"" % (results["target"]["file"]["sha1"])
            if results["target"]["file"].has_key("sha256") and results["target"]["file"]["sha256"]:
                cmd = cmd + " -t \"sha256:%s\"" % (results["target"]["file"]["sha256"])
            if results["target"]["file"].has_key("sha512") and results["target"]["file"]["sha512"]:
                cmd = cmd + " -t \"sha512:%s\"" % (results["target"]["file"]["sha512"])
            if results["target"]["file"].has_key("clamav") and results["target"]["file"]["clamav"]:
                cmd = cmd + " -t \"clamav:%s\"" % (re.sub(r"[\W]","_",results["target"]["file"]["clamav"]))
            if results["static"].has_key("pe_imphash") and results["static"]["pe_imphash"]:
                cmd = cmd + " -t \"pehash:%s\"" % (results["static"]["pe_imphash"])
            if results["target"]["file"].has_key("yara"):
                for entry in results["target"]["file"]["yara"]:
                    cmd = cmd + " -t \"yara:%s\"" % entry["name"]
        try:                   
            ret,stdout,stderr = self.cmd_wrapper(cmd)
            if ret == 0:
               log.warning("moloch: imported pcap %s" % (self.pcap_path))
            else:
                log.warning("moloch-capture returned a Exit Value Other than Zero %s" % (stderr))
        except Exception,e:
            log.warning("Unable to Run moloch-capture: %s" % e)

        time.sleep(5)
         
        if results.has_key('suricata'):
           if results["suricata"].has_key("alerts"):
               for alert in results["suricata"]["alerts"]:
                       proto =  alert["proto"]
                       if proto:
                           tmpdict = {}
                           cproto = ""
                           if proto == "UDP" or proto == "TCP" or proto == "6" or proto == "17":
                               tmpdict['src_ip'] = alert['src_ip']
                               tmpdict['src_port'] = alert['src_port'] 
                               tmpdict['dest_ip'] = alert['dest_ip']
                               tmpdict['dest_port'] = alert['dest_port']
                               if proto == "UDP" or proto == "17":
                                   tmpdict['cproto'] = "udp"
                                   tmpdict['nproto'] = 17
                               elif proto == "TCP" or proto == "6":
                                   tmpdict['cproto'] = "tcp"
                                   tmpdict['nproto'] = 6
                               tmpdict['expression'] = "ip==%s && ip==%s && port==%s && port==%s && tags==\"%s:%s\" && tags=\"%s\"" % (tmpdict['src_ip'],tmpdict['dest_ip'],tmpdict['src_port'],tmpdict['dest_port'],self.CUCKOO_INSTANCE_TAG,self.task_id,tmpdict['cproto'])
                               tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['src_ip']))[0] + tmpdict['src_port'] + struct.unpack('!L',socket.inet_aton(tmpdict['dest_ip']))[0] + tmpdict['dest_port']
                           elif proto == "ICMP" or proto == "1":
                               tmpdict['src'] = m.group('src')
                               tmpdict['dst'] = m.group('dst')
                               tmpdict['cproto'] = "icmp"
                               tmpdict['nproto'] = 1
                               tmpdict['expression'] = "ip==%s && ip==%s && tags==\"%s:%s\" && tags=\"%s\"" % (tmpdict['src_ip'],tmpdict['dest_ip'],self.CUCKOO_INSTANCE_TAG,self.task_id,tmpdict['cproto'])
                               tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['src_ip']))[0] + struct.unpack('!L',socket.inet_aton(tmpdict['dest_ip']))[0]

                           if self.alerthash.has_key(tmpdict['hash']):
                               if  alert["alert"]["signature_id"] not in self.alerthash[tmpdict['hash']]['sids']:
                                   self.alerthash[tmpdict['hash']]['sids'].append("suri_sid:%s" % (alert["alert"]["signature_id"]))
                                   self.alerthash[tmpdict['hash']]['msgs'].append("suri_msg:%s" % (re.sub(r"[\W]","_",alert["alert"]["signature"])))
                           else:
                               self.alerthash[tmpdict['hash']] = copy.deepcopy(tmpdict)
                               self.alerthash[tmpdict['hash']]['sids']=[]
                               self.alerthash[tmpdict['hash']]['msgs']=[]
                               self.alerthash[tmpdict['hash']]['sids'].append("suri_sid:%s" % (alert["alert"]["signature_id"]))
                               self.alerthash[tmpdict['hash']]['msgs'].append("suri_msg:%s" % (re.sub(r"[\W]","_",alert["alert"]["signature"])))
               for entry in self.alerthash:
                   tags = ','.join(map(str,self.alerthash[entry]['sids']) + map(str,self.alerthash[entry]['msgs']))
                   if tags:
                       self.update_tags(tags,self.alerthash[entry]['expression'])

           if results["suricata"].has_key("files"):
               for entry in results["suricata"]["files"]:
                   if  entry.has_key("file_info"):
                       proto = entry["protocol"]
                       if proto:
                           tmpdict = {}
                           cproto = ""
                           tmpdict['cproto'] = "tcp"
                           tmpdict['nproto'] = 6
                           tmpdict['src_ip'] = entry['srcip']
                           tmpdict['src_port'] = entry['sp']
                           tmpdict['dest_ip'] = entry['dstip']
                           tmpdict['dest_port'] = entry['dp']
                           tmpdict['expression'] = "ip==%s && ip==%s && port==%s && port==%s && tags==\"%s:%s\" && tags=\"%s\"" % (tmpdict['src_ip'],tmpdict['dest_ip'],tmpdict['src_port'],tmpdict['dest_port'],self.CUCKOO_INSTANCE_TAG,self.task_id,tmpdict['cproto'])
                           tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['src_ip']))[0] + tmpdict['src_port'] + struct.unpack('!L',socket.inet_aton(tmpdict['dest_ip']))[0] + tmpdict['dest_port']

                           if not self.fileshash.has_key(tmpdict['hash']):
                               self.fileshash[tmpdict['hash']] = copy.deepcopy(tmpdict)
                               self.fileshash[tmpdict['hash']]['clamav']=[]
                               self.fileshash[tmpdict['hash']]['md5']=[]
                               self.fileshash[tmpdict['hash']]['sha1']=[]
                               self.fileshash[tmpdict['hash']]['sha256']=[]
                               self.fileshash[tmpdict['hash']]['crc32']=[]
                               self.fileshash[tmpdict['hash']]['ssdeep']=[]
                               self.fileshash[tmpdict['hash']]['yara']=[]
                           if entry["file_info"]["clamav"] and entry["file_info"]["clamav"] not in self.fileshash[tmpdict['hash']]['clamav']:
                               self.fileshash[tmpdict['hash']]['clamav'].append("clamav:%s" % (re.sub(r"[\W]","_",entry["file_info"]["clamav"])))
                           if entry["file_info"]["md5"] and entry["file_info"]["md5"] not in self.fileshash[tmpdict['hash']]['md5']:
                               self.fileshash[tmpdict['hash']]['md5'].append("md5:%s" % (entry["file_info"]["md5"]))
                           if entry["file_info"]["sha1"] and entry["file_info"]["sha1"] not in self.fileshash[tmpdict['hash']]['sha1']:
                               self.fileshash[tmpdict['hash']]['sha1'].append("sha1:%s" % (entry["file_info"]["sha1"]))
                           if entry["file_info"]["sha256"] and entry["file_info"]["sha256"] not in self.fileshash[tmpdict['hash']]['sha256']:
                               self.fileshash[tmpdict['hash']]['sha256'].append("sha256:%s" % (entry["file_info"]["sha256"]))
                           if entry["file_info"]["crc32"] and entry["file_info"]["crc32"] not in self.fileshash[tmpdict['hash']]['crc32']:
                               self.fileshash[tmpdict['hash']]['crc32'].append("crc32:%s" % (entry["file_info"]["crc32"]))
                           if entry["file_info"]["ssdeep"] and entry["file_info"]["ssdeep"] not in self.fileshash[tmpdict['hash']]['ssdeep']:
                               self.fileshash[tmpdict['hash']]['ssdeep'].append("ssdeep:%s" % (entry["file_info"]["ssdeep"]))
                           if entry["file_info"]["yara"]:
                                  for sign in entry["file_info"]["yara"]:
                                      if sign["name"] not in self.fileshash[tmpdict['hash']]['yara']:
                                          self.fileshash[tmpdict['hash']]['yara'].append("yara:%s" % (sign["name"]))

               for entry in self.fileshash:
                   tags = ','.join(map(str,self.fileshash[entry]['clamav']) + map(str,self.fileshash[entry]['md5']) + map(str,self.fileshash[entry]['sha1']) + map(str,self.fileshash[entry]['sha256']) + map(str,self.fileshash[entry]['crc32']) + map(str,self.fileshash[entry]['ssdeep']) + map(str,self.fileshash[entry]['yara']))
                   if tags:
                       self.update_tags(tags,self.fileshash[entry]['expression'])                
        return {} 
