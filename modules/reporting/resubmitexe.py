import os
import re
import pprint
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.core.database import Database


class ReSubmitExtractedEXE(Report):
    def run(self, results):
        filesdict = {}
        report = dict(results)         
        if report["target"]["category"] == "url":
            for dropped in report["dropped"]:
                if os.path.isfile(dropped["path"]):
                    if re.search(r"PE32 executable",dropped["type"]) != None and re.search(r"\(DLL\)",dropped["type"]) == None:
                        if not filesdict.has_key(dropped['sha256']):
                            filesdict[dropped['sha256']] = dropped['path']
            
        if report.has_key("suricata") and report["suricata"]:
            if report["suricata"].has_key("files") and report["suricata"]["files"]:
                for suricata_file_e in results["suricata"]["files"]:
                    if suricata_file_e.has_key("file_info"):
                        tmp_suricata_file_d = dict(suricata_file_e)
                        if os.path.isfile(suricata_file_e["file_info"]["path"]):
                            if re.search(r"PE32 executable",suricata_file_e["file_info"]["type"]) != None and re.search(r"\(DLL\)",suricata_file_e["file_info"]["type"]) == None:
                                if not filesdict.has_key(suricata_file_e["file_info"]["sha256"]):
                                    filesdict[suricata_file_e["file_info"]["sha256"]] = suricata_file_e["file_info"]["path"]

        db = Database()

        for e in filesdict:
            if not File(filesdict[e]).get_size():
                continue
            if not db.find_sample(sha256=e) is None:
                continue

            task_id = db.add_path(file_path=filesdict[e],
                                  package='exe',
                                  timeout=200,
                                  options=None,
                                  priority=1,
                                  machine=None,
                                  platform=None,
                                  custom=None,
                                  memory=False,
                                  enforce_timeout=False,
                                  clock=None,
                                  tags=None)

            if task_id:
                print("Success" + u": File \"{0}\" added as task with ID {1}".format(filesdict[e], task_id))
            else:
                print("Error" + ": adding task to database")
