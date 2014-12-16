# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import os
import json
from django.conf import settings

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config

cfg = Config(cfg=os.path.join(CUCKOO_ROOT, "conf", "reporting.conf")).mongodb
moloch_cfg = Config(cfg=os.path.join(CUCKOO_ROOT, "conf", "reporting.conf")).moloch
aux_cfg =  Config(cfg=os.path.join(CUCKOO_ROOT, "conf", "auxiliary.conf"))
vtdl_cfg = Config(cfg=os.path.join(CUCKOO_ROOT, "conf", "auxiliary.conf")).virustotaldl
# Checks if mongo reporting is enabled in Cuckoo.
if not cfg.get("enabled"):
    raise Exception("Mongo reporting module is not enabled in cuckoo, aborting!")

# Get connection options from reporting.conf.
settings.MONGO_HOST = cfg.get("host", "127.0.0.1")
settings.MONGO_PORT = cfg.get("port", 27017)

settings.MONGO_PORT = cfg.get("port", 27017)
settings.MOLOCH_BASE = moloch_cfg.get("base", None)
settings.MOLOCH_NODE = moloch_cfg.get("node", None)
settings.MOLOCH_ENABLED = moloch_cfg.get("enabled", False)

settings.GATEWAYS = aux_cfg.get("gateways")
settings.VTDL_ENABLED = vtdl_cfg.get("enabled",False)
settings.VTDL_KEY = vtdl_cfg.get("dlkey",None)
settings.VTDL_PATH = vtdl_cfg.get("dlpath",None)
