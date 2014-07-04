# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import re
from pprint import pprint
from django.conf import settings
from django.template import RequestContext
from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe

import pymongo
from bson.objectid import ObjectId
from django.core.exceptions import PermissionDenied
from gridfs import GridFS
from urllib import quote
sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING

results_db = pymongo.connection.Connection(settings.MONGO_HOST, settings.MONGO_PORT).cuckoo
fs = GridFS(results_db)

@require_safe
def index(request):
    db = Database()
    tasks_files = db.list_tasks(limit=50, category="file", not_status=TASK_PENDING)
    tasks_urls = db.list_tasks(limit=50, category="url", not_status=TASK_PENDING)

    analyses_files = []
    analyses_urls = []

    if tasks_files:
        for task in tasks_files:
            new = task.to_dict()
            new["sample"] = db.view_sample(new["sample_id"]).to_dict()
            if db.view_errors(task.id):
                new["errors"] = True

            rtmp = results_db.analysis.find_one({"info.id": int(new["id"])},{"virustotal_summary": 1, "suri_tls_cnt": 1, "suri_alert_cnt": 1, "suri_http_cnt": 1, "suri_file_cnt": 1, "suricata.http_log_id": 1, "suricata.tls_log_id": 1, "suricata.fast_log_id": 1, "suricata.file_log_id": 1, "mlist_cnt": 1, "network.pcap_id":1},sort=[("_id", pymongo.DESCENDING)])
            if rtmp:
                if rtmp.has_key("virustotal_summary") and rtmp["virustotal_summary"]:
                    new["virustotal_summary"] = rtmp["virustotal_summary"]
                if rtmp.has_key("suri_tls_cnt") and rtmp["suri_tls_cnt"]:
                    new["suri_tls_cnt"] = rtmp["suri_tls_cnt"]
                if rtmp.has_key("suri_alert_cnt") and rtmp["suri_alert_cnt"]:
                    new["suri_alert_cnt"] = rtmp["suri_alert_cnt"]
                if rtmp.has_key("suri_file_cnt") and rtmp["suri_file_cnt"]:
                    new["suri_file_cnt"] = rtmp["suri_file_cnt"]
                if rtmp.has_key("suri_http_cnt") and rtmp["suri_http_cnt"]:
                    new["suri_http_cnt"] = rtmp["suri_http_cnt"]
                if rtmp.has_key("suricata") and rtmp["suricata"]:
                    if rtmp["suricata"].has_key("http_log_id") and rtmp["suricata"]["http_log_id"]:
                        new["suricata_http_log_id"] = rtmp["suricata"]["http_log_id"]
                    if rtmp["suricata"].has_key("tls_log_id") and rtmp["suricata"]["tls_log_id"]:
                        new["suricata_tls_log_id"] = rtmp["suricata"]["tls_log_id"]
                    if rtmp["suricata"].has_key("fast_log_id") and rtmp["suricata"]["fast_log_id"]:
                        new["suricata_fast_log_id"] = rtmp["suricata"]["fast_log_id"]
                    if  rtmp["suricata"].has_key("file_log_id") and rtmp["suricata"]["file_log_id"]:
                        new["suricata_file_log_id"] = rtmp["suricata"]["file_log_id"]
                if rtmp.has_key("mlist_cnt") and rtmp["mlist_cnt"]:
                    new["mlist_cnt"] = rtmp["mlist_cnt"]
                if rtmp.has_key("network") and rtmp["network"].has_key("pcap_id") and rtmp["network"]["pcap_id"]:
                    new["pcap_id"] = rtmp["network"]["pcap_id"]
            if settings.MOLOCH_ENABLED:
                if settings.MOLOCH_BASE[-1] != "/":
                    settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
                new["moloch_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE,new["id"]),safe='')
            analyses_files.append(new)

    if tasks_urls:
        for task in tasks_urls:
            new = task.to_dict()

            if db.view_errors(task.id):
                new["errors"] = True
            rtmp = results_db.analysis.find_one({"info.id": int(new["id"])},{"virustotal_summary": 1, "suri_tls_cnt": 1, "suri_alert_cnt": 1, "suri_http_cnt": 1, "suri_file_cnt": 1, "suricata.http_log_id": 1, "suricata.tls_log_id": 1, "suricata.fast_log_id": 1, "suricata.file_log_id": 1, "mlist_cnt": 1, "network.pcap_id":1},sort=[("_id", pymongo.DESCENDING)])
            if rtmp:
                if rtmp.has_key("virustotal_summary") and rtmp["virustotal_summary"]:
                    new["virustotal_summary"] = rtmp["virustotal_summary"]
                if rtmp.has_key("suri_tls_cnt") and rtmp["suri_tls_cnt"]:
                    new["suri_tls_cnt"] = rtmp["suri_tls_cnt"]
                if rtmp.has_key("suri_alert_cnt") and rtmp["suri_alert_cnt"]:
                    new["suri_alert_cnt"] = rtmp["suri_alert_cnt"]
                if rtmp.has_key("suri_file_cnt") and rtmp["suri_file_cnt"]:
                    new["suri_file_cnt"] = rtmp["suri_file_cnt"]
                if rtmp.has_key("suri_http_cnt") and rtmp["suri_http_cnt"]:
                    new["suri_http_cnt"] = rtmp["suri_http_cnt"]
                if rtmp.has_key("suricata") and rtmp["suricata"]:
                    if rtmp["suricata"].has_key("http_log_id") and rtmp["suricata"]["http_log_id"]:
                        new["suricata_http_log_id"] = rtmp["suricata"]["http_log_id"]
                    if rtmp["suricata"].has_key("tls_log_id") and rtmp["suricata"]["tls_log_id"]:
                        new["suricata_tls_log_id"] = rtmp["suricata"]["tls_log_id"]
                    if rtmp["suricata"].has_key("fast_log_id") and rtmp["suricata"]["fast_log_id"]:
                        new["suricata_fast_log_id"] = rtmp["suricata"]["fast_log_id"]
                    if  rtmp["suricata"].has_key("file_log_id") and rtmp["suricata"]["file_log_id"]:
                        new["suricata_file_log_id"] = rtmp["suricata"]["file_log_id"]
                if rtmp.has_key("mlist_cnt") and rtmp["mlist_cnt"]:
                    new["mlist_cnt"] = rtmp["mlist_cnt"]
                if rtmp.has_key("network") and rtmp["network"].has_key("pcap_id") and rtmp["network"]["pcap_id"]:
                    new["pcap_id"] = rtmp["network"]["pcap_id"]
            if settings.MOLOCH_ENABLED:
                if settings.MOLOCH_BASE[-1] != "/":
                    settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
                new["moloch_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE,new["id"]),safe='')
            analyses_urls.append(new)

    return render_to_response("analysis/index.html",
                              {"files": analyses_files, "urls": analyses_urls},
                              context_instance=RequestContext(request))

@require_safe
def pending(request):
    db = Database()
    tasks = db.list_tasks(status=TASK_PENDING)

    pending = []
    for task in tasks:
        pending.append(task.to_dict())

    return render_to_response("analysis/pending.html",
                              {"tasks": pending},
                              context_instance=RequestContext(request))

@require_safe
def chunk(request, task_id, pid, pagenum):
    try:
        pid, pagenum = int(pid), int(pagenum)-1
    except:
        raise PermissionDenied

    if request.is_ajax():
        record = results_db.analysis.find_one(
            {
                "info.id": int(task_id),
                "behavior.processes.process_id": pid
            },
            {
                "behavior.processes.process_id": 1,
                "behavior.processes.calls": 1
            }
        )

        if not record:
            raise PermissionDenied

        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == pid:
                process = pdict

        if not process:
            raise PermissionDenied

        objectid = process["calls"][pagenum]
        chunk = results_db.calls.find_one({"_id": ObjectId(objectid)})

        return render_to_response("analysis/behavior/_chunk.html",
                                  {"chunk": chunk},
                                  context_instance=RequestContext(request))
    else:
        raise PermissionDenied
        
        
@require_safe
def filtered_chunk(request, task_id, pid, category):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    @param pid: pid you want calls
    @param category: call category type
    """
    if request.is_ajax():
        # Search calls related to your PID.
        record = results_db.analysis.find_one(
            {"info.id": int(task_id), "behavior.processes.process_id": int(pid)},
            {"behavior.processes.process_id": 1, "behavior.processes.calls": 1}
        )

        if not record:
            raise PermissionDenied

        # Extract embedded document related to your process from response collection.
        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == int(pid):
                process = pdict

        if not process:
            raise PermissionDenied

        # Create empty process dict for AJAX view.
        filtered_process = {"process_id": pid, "calls": []}

        # Populate dict, fetching data from all calls and selecting only appropriate category.
        for call in process["calls"]:
            chunk = results_db.calls.find_one({"_id": call})
            for call in chunk["calls"]:
                if call["category"] == category:
                    filtered_process["calls"].append(call)

        return render_to_response("analysis/behavior/_chunk.html",
                                  {"chunk": filtered_process},
                                  context_instance=RequestContext(request))
    else:
        raise PermissionDenied

@require_safe
def report(request, task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))

    return render_to_response("analysis/report.html",
                              {"analysis": report},
                              context_instance=RequestContext(request))

@require_safe
def file(request, category, object_id):
    file_object = results_db.fs.files.find_one({"_id": ObjectId(object_id)})

    if file_object:
        content_type = file_object.get("contentType", "application/octet-stream")
        file_item = fs.get(ObjectId(file_object["_id"]))

        file_name = file_item.sha256
        if category == "pcap":
            file_name += ".pcap"
            content_type = file_object.get("contentType", "application/vnd.tcpdump.pcap")
        elif category == "zip":
            file_name += ".zip"
        elif category == "screenshot":
            file_name += ".jpg"
        elif category == "text":
            file_name += ".txt"
            content_type = file_object.get("contentType", "text/plain")
        else:
            file_name += ".bin"

        response = HttpResponse(file_item.read(), content_type=content_type)
        response["Content-Disposition"] = "attachment; filename={0}".format(file_name)

        return response
    else:
        return render_to_response("error.html",
                                  {"error": "File not found"},
                                  context_instance=RequestContext(request))

@require_safe
def viewfile(request, category, object_id):
    file_object = results_db.fs.files.find_one({"_id": ObjectId(object_id)})

    if file_object:
        content_type = file_object.get("contentType", "text/plain") 
        file_item = fs.get(ObjectId(file_object["_id"]))

        file_name = file_item.sha256
        if category == "text":
            file_name += ".txt"
        else:
            file_name += ".bin"

        response = HttpResponse(file_item.read(), content_type=content_type)
        return response
    else:
        return render_to_response("error.html",
                                  {"error": "File not found"},
                                  context_instance=RequestContext(request))

def search(request):
    if "search" in request.POST:
        error = None

        try:
            term, value = request.POST["search"].strip().split(":", 1)
        except ValueError:
            term = ""
            value = request.POST["search"].strip()

        if term:
            # Check on search size.
            if len(value) < 3:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "error": "Search term too short, minimum 3 characters required"},
                                          context_instance=RequestContext(request))
            # name:foo or name: foo
            value = value.lstrip()

            # Search logic.
            if term == "name":
                records = results_db.analysis.find({"target.file.name": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "type":
                records = results_db.analysis.find({"target.file.type": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "ssdeep":
                records = results_db.analysis.find({"target.file.ssdeep": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "crc32":
                records = results_db.analysis.find({"target.file.crc32": value}).sort([["_id", -1]])
            elif term == "file":
                records = results_db.analysis.find({"behavior.summary.files": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "key":
                records = results_db.analysis.find({"behavior.summary.keys": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "mutex":
                records = results_db.analysis.find({"behavior.summary.mutexes": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "domain":
                records = results_db.analysis.find({"network.domains.domain": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "ip":
                records = results_db.analysis.find({"network.hosts": value}).sort([["_id", -1]])
            elif term == "signature":
                records = results_db.analysis.find({"signatures.description": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "url":
                records = results_db.analysis.find({"target.url": value}).sort([["_id", -1]])
            elif term == "imphash":
                records = results_db.analysis.find({"static.pe_imphash": value}).sort([["_id", -1]])
            elif term == "surialert":
                records = results_db.analysis.find({"suricata.alerts": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "surihttp":
                records = results_db.analysis.find({"suricata.http": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "suritls":
                records = results_db.analysis.find({"suricata.tls": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "clamav":
                records = results_db.analysis.find({"target.file.clamav": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "yaraname":
                records = results_db.analysis.find({"target.file.yara.name": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "strings":
                records = results_db.analysis.find({"strings": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "virustotal":
                records = results_db.analysis.find({"virustotal.results.sig": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            else:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "error": "Invalid search term: %s" % term},
                                          context_instance=RequestContext(request))
        else:
            if re.match(r"^([a-fA-F\d]{32})$", value):
                records = results_db.analysis.find({"target.file.md5": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{40})$", value):
                records = results_db.analysis.find({"target.file.sha1": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{64})$", value):
                records = results_db.analysis.find({"target.file.sha256": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{128})$", value):
                records = results_db.analysis.find({"target.file.sha512": value}).sort([["_id", -1]])
            else:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": None,
                                           "error": "Unable to recognize the search syntax"},
                                          context_instance=RequestContext(request))

        # Get data from cuckoo db.
        db = Database()
        analyses = []
        for result in records:
            new = db.view_task(result["info"]["id"])

            if not new:
                continue

            new = new.to_dict()
            if result["info"]["category"] == "file":
                if new["sample_id"]:
                    sample = db.view_sample(new["sample_id"])
                    if sample:
                        new["sample"] = sample.to_dict()

            rtmp = results_db.analysis.find_one({"info.id": int(new["id"])},{"virustotal_summary": 1, "suri_tls_cnt": 1, "suri_alert_cnt": 1, "suri_http_cnt": 1, "suri_file_cnt": 1, "suricata.http_log_id": 1, "suricata.tls_log_id": 1, "suricata.fast_log_id": 1, "suricata.file_log_id": 1, "mlist_cnt": 1, "network.pcap_id":1},sort=[("_id", pymongo.DESCENDING)])
            if rtmp:
                if rtmp.has_key("virustotal_summary") and rtmp["virustotal_summary"]:
                    new["virustotal_summary"] = rtmp["virustotal_summary"]
                if rtmp.has_key("suri_tls_cnt") and rtmp["suri_tls_cnt"]:
                    new["suri_tls_cnt"] = rtmp["suri_tls_cnt"]
                if rtmp.has_key("suri_alert_cnt") and rtmp["suri_alert_cnt"]:
                    new["suri_alert_cnt"] = rtmp["suri_alert_cnt"]
                if rtmp.has_key("suri_file_cnt") and rtmp["suri_file_cnt"]:
                    new["suri_file_cnt"] = rtmp["suri_file_cnt"]
                if rtmp.has_key("suri_http_cnt") and rtmp["suri_http_cnt"]:
                    new["suri_http_cnt"] = rtmp["suri_http_cnt"]
                if rtmp.has_key("suricata") and rtmp["suricata"]:
                    if rtmp["suricata"].has_key("http_log_id") and rtmp["suricata"]["http_log_id"]:
                        new["suricata_http_log_id"] = rtmp["suricata"]["http_log_id"]
                    if rtmp["suricata"].has_key("tls_log_id") and rtmp["suricata"]["tls_log_id"]:
                        new["suricata_tls_log_id"] = rtmp["suricata"]["tls_log_id"]
                    if rtmp["suricata"].has_key("fast_log_id") and rtmp["suricata"]["fast_log_id"]:
                        new["suricata_fast_log_id"] = rtmp["suricata"]["fast_log_id"]
                    if  rtmp["suricata"].has_key("file_log_id") and rtmp["suricata"]["file_log_id"]:
                        new["suricata_file_log_id"] = rtmp["suricata"]["file_log_id"]
                if rtmp.has_key("mlist_cnt") and rtmp["mlist_cnt"]:
                    new["mlist_cnt"] = rtmp["mlist_cnt"]
                if rtmp.has_key("network") and rtmp["network"].has_key("pcap_id") and rtmp["network"]["pcap_id"]:
                    new["pcap_id"] = rtmp["network"]["pcap_id"]
            if settings.MOLOCH_ENABLED:
                if settings.MOLOCH_BASE[-1] != "/":
                    settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
                new["moloch_url"] = settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE,new["id"]),safe='')
            analyses.append(new)
        return render_to_response("analysis/search.html",
                                  {"analyses": analyses,
                                   "term": request.POST["search"],
                                   "error": None},
                                  context_instance=RequestContext(request))
    else:
        return render_to_response("analysis/search.html",
                                  {"analyses": None,
                                   "term": None,
                                   "error": None},
                                  context_instance=RequestContext(request))
