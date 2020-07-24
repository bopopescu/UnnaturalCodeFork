#!/usr/bin/python -S
#
# Copyright 2011 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

"""Main distro publishing script."""

import _pythonpath

from lp.archivepublisher.scripts.publish_ftpmain import PublishFTPMain


if __name__ == '__main__':
    script = PublishFTPMain(
        "publish-ftpmain", 'publish_ftpmain')
    script.lock_and_run()
