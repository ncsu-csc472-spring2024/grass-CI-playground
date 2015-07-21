"""
TEST:      test_addons_toolboxes.py

AUTHOR(S): Vaclav Petras <wenzeslaus gmail com>

PURPOSE:   Test for g.extension toolboxes handling

COPYRIGHT: (C) 2015 Vaclav Petras, and by the GRASS Development Team

           This program is free software under the GNU General Public
           License (>=v2). Read the file COPYING that comes with GRASS
           for details.
"""

from grass.gunittest.case import TestCase
from grass.gunittest.main import test
from grass.gunittest.gmodules import SimpleModule

import os

FULL_TOOLBOXES_OUTPUT = """\
Hydrology (HY)
* r.stream.basins
* r.stream.channel
* r.stream.distance
* r.stream.order
* r.stream.segment
* r.stream.slope
* r.stream.snap
* r.stream.stats
mcda (MC)
* r.mcda.ahp
* r.mcda.roughset
* r.mcda.input
* r.mcda.output
"""


class TestToolboxesMetadata(TestCase):

    url = 'file://' + os.path.abspath('data')

    def test_limits(self):
        """Test if results is in expected limits"""
        module = SimpleModule('g.extension', flags='lt', svnurl=self.url)
        self.assertModule(module)
        stdout = module.outputs.stdout
        self.assertLooksLike(stdout, FULL_TOOLBOXES_OUTPUT)


if __name__ == '__main__':
    test()