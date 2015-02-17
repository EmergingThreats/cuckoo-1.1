# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "analysis.views.index"),
    url(r"^(?P<task_id>\d+)/$", "analysis.views.report"),
    url(r"^surialert/(?P<task_id>\d+)/$", "analysis.views.surialert"),
    url(r"^surihttp/(?P<task_id>\d+)/$", "analysis.views.surihttp"),
    url(r"^suritls/(?P<task_id>\d+)/$", "analysis.views.suritls"),
    url(r"^surifiles/(?P<task_id>\d+)/$","analysis.views.surifiles"),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", "analysis.views.chunk"),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/$", "analysis.views.filtered_chunk"),
    url(r"^search/$", "analysis.views.search"),
    url(r"^pending/$", "analysis.views.pending"),
)
