# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 Claudio Guarnieri, Bjarni R. Einarsson
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import logging

from mvt.common.indicators import Indicators
from mvt.common.module import run_module
from mvt.ios.modules.mixed.viber import Viber

from ..utils import get_ios_backup_folder


class TestViberModule:
    def test_viber(self):
        m = Viber(target_path=get_ios_backup_folder())
        m.unique_links = False  # Allow duplicate links in our output
        run_module(m)
        assert len(m.results) == 2  # Hi there + I'd like to invite...
        assert len(m.timeline) == 2
        assert len(m.detected) == 0
        assert "tinyurl.com" in m.results[1]["links"][0]
        assert len(m.results[1]["links"]) == 2  # Ensure we picked up the ZCLIENTMETADATA links

    def test_detection(self, indicator_file):
        m = Viber(target_path=get_ios_backup_folder())
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        ind.ioc_collections[0]["domains"].append("kingdom-deals.com")
        m.indicators = ind
        run_module(m)
        assert len(m.detected) == 1
