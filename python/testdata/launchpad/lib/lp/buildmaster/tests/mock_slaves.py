# Copyright 2009-2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

"""Mock Build objects for tests soyuz buildd-system."""

__metaclass__ = type

__all__ = [
    'AbortingSubordinate',
    'BrokenSubordinate',
    'BuildingSubordinate',
    'DeadProxy',
    'LostBuildingBrokenSubordinate',
    'make_publisher',
    'MockBuilder',
    'OkSubordinate',
    'SubordinateTestHelpers',
    'TrivialBehavior',
    'WaitingSubordinate',
    ]

import os
import types
import xmlrpclib

import fixtures
from lpbuildd.tests.harness import BuilddSubordinateTestSetup
from testtools.content import Content
from testtools.content_type import UTF8_TEXT
from twisted.internet import defer
from twisted.web import xmlrpc

from lp.buildmain.interactor import BuilderSubordinate
from lp.buildmain.interfaces.builder import CannotFetchFile
from lp.services.config import config
from lp.testing.sampledata import I386_ARCHITECTURE_NAME


def make_publisher():
    """Make a Soyuz test publisher."""
    # Avoid circular imports.
    from lp.soyuz.tests.test_publishing import SoyuzTestPublisher
    return SoyuzTestPublisher()


class MockBuilder:
    """Emulates a IBuilder class."""

    def __init__(self, name='mock-builder', builderok=True, manual=False,
                 virtualized=True, vm_host=None, url='http://fake:0000'):
        self.currentjob = None
        self.builderok = builderok
        self.manual = manual
        self.url = url
        self.name = name
        self.virtualized = virtualized
        self.vm_host = vm_host
        self.failnotes = None

    def failBuilder(self, reason):
        self.builderok = False
        self.failnotes = reason


# XXX: It would be *really* nice to run some set of tests against the real
# BuilderSubordinate and this one to prevent interface skew.
class OkSubordinate:
    """An idle mock subordinate that prints information about itself.

    The architecture tag can be customised during initialization."""

    def __init__(self, arch_tag=I386_ARCHITECTURE_NAME):
        self.call_log = []
        self.arch_tag = arch_tag

    def status(self):
        return defer.succeed(('BuilderStatus.IDLE', ''))

    def ensurepresent(self, sha1, url, user=None, password=None):
        self.call_log.append(('ensurepresent', url, user, password))
        return defer.succeed((True, None))

    def build(self, buildid, buildtype, chroot, filemap, args):
        self.call_log.append(
            ('build', buildid, buildtype, chroot, filemap.keys(), args))
        info = 'OkSubordinate BUILDING'
        return defer.succeed(('BuildStatus.Building', info))

    def echo(self, *args):
        self.call_log.append(('echo',) + args)
        return defer.succeed(args)

    def clean(self):
        self.call_log.append('clean')
        return defer.succeed(None)

    def abort(self):
        self.call_log.append('abort')
        return defer.succeed(None)

    def info(self):
        self.call_log.append('info')
        return defer.succeed(('1.0', self.arch_tag, 'debian'))

    def resume(self):
        self.call_log.append('resume')
        return defer.succeed(("", "", 0))

    def sendFileToSubordinate(self, sha1, url, username="", password=""):
        d = self.ensurepresent(sha1, url, username, password)

        def check_present((present, info)):
            if not present:
                raise CannotFetchFile(url, info)

        return d.addCallback(check_present)

    def cacheFile(self, logger, libraryfilealias):
        return self.sendFileToSubordinate(
            libraryfilealias.content.sha1, libraryfilealias.http_url)

    def getFiles(self, filemap):
        dl = defer.gatherResults([
            self.getFile(builder_file, filemap[builder_file])
            for builder_file in filemap])
        return dl


class BuildingSubordinate(OkSubordinate):
    """A mock subordinate that looks like it's currently building."""

    def __init__(self, build_id='1-1'):
        super(BuildingSubordinate, self).__init__()
        self.build_id = build_id

    def status(self):
        self.call_log.append('status')
        buildlog = xmlrpclib.Binary("This is a build log")
        return defer.succeed(
            ('BuilderStatus.BUILDING', self.build_id, buildlog))

    def getFile(self, sum, file_to_write):
        self.call_log.append('getFile')
        if sum == "buildlog":
            if isinstance(file_to_write, types.StringTypes):
                file_to_write = open(file_to_write, 'wb')
            file_to_write.write("This is a build log")
            file_to_write.close()
        return defer.succeed(None)


class WaitingSubordinate(OkSubordinate):
    """A mock subordinate that looks like it's currently waiting."""

    def __init__(self, state='BuildStatus.OK', dependencies=None,
                 build_id='1-1', filemap=None):
        super(WaitingSubordinate, self).__init__()
        self.state = state
        self.dependencies = dependencies
        self.build_id = build_id
        if filemap is None:
            self.filemap = {}
        else:
            self.filemap = filemap

        # By default, the subordinate only has a buildlog, but callsites
        # can update this list as needed.
        self.valid_file_hashes = ['buildlog']

    def status(self):
        self.call_log.append('status')
        return defer.succeed((
            'BuilderStatus.WAITING', self.state, self.build_id, self.filemap,
            self.dependencies))

    def getFile(self, hash, file_to_write):
        self.call_log.append('getFile')
        if hash in self.valid_file_hashes:
            content = "This is a %s" % hash
            if isinstance(file_to_write, types.StringTypes):
                file_to_write = open(file_to_write, 'wb')
            file_to_write.write(content)
            file_to_write.close()
        return defer.succeed(None)


class AbortingSubordinate(OkSubordinate):
    """A mock subordinate that looks like it's in the process of aborting."""

    def status(self):
        self.call_log.append('status')
        return defer.succeed(('BuilderStatus.ABORTING', '1-1'))


class LostBuildingBrokenSubordinate:
    """A mock subordinate building bogus Build/BuildQueue IDs that can't be aborted.

    When 'aborted' it raises an xmlrpclib.Fault(8002, 'Could not abort')
    """

    def __init__(self):
        self.call_log = []

    def status(self):
        self.call_log.append('status')
        return defer.succeed(('BuilderStatus.BUILDING', '1000-10000'))

    def abort(self):
        self.call_log.append('abort')
        return defer.fail(xmlrpclib.Fault(8002, "Could not abort"))

    def resume(self):
        self.call_log.append('resume')
        return defer.succeed(("", "", 0))


class BrokenSubordinate:
    """A mock subordinate that reports that it is broken."""

    def __init__(self):
        self.call_log = []

    def status(self):
        self.call_log.append('status')
        return defer.fail(xmlrpclib.Fault(8001, "Broken subordinate"))


class TrivialBehavior:

    def getBuildCookie(self):
        return 'trivial'


class DeadProxy(xmlrpc.Proxy):
    """An xmlrpc.Proxy that doesn't actually send any messages.

    Used when you want to test timeouts, for example.
    """

    def callRemote(self, *args, **kwargs):
        return defer.Deferred()


class SubordinateTestHelpers(fixtures.Fixture):

    # The URL for the XML-RPC service set up by `BuilddSubordinateTestSetup`.
    BASE_URL = 'http://localhost:8221'
    TEST_URL = '%s/rpc/' % (BASE_URL,)

    def getServerSubordinate(self):
        """Set up a test build subordinate server.

        :return: A `BuilddSubordinateTestSetup` object.
        """
        tachandler = self.useFixture(BuilddSubordinateTestSetup())
        self.addDetail(
            'xmlrpc-log-file',
            Content(
                UTF8_TEXT,
                lambda: open(tachandler.logfile, 'r').readlines()))
        return tachandler

    def getClientSubordinate(self, reactor=None, proxy=None):
        """Return a `BuilderSubordinate` for use in testing.

        Points to a fixed URL that is also used by `BuilddSubordinateTestSetup`.
        """
        return BuilderSubordinate.makeBuilderSubordinate(
            self.BASE_URL, 'vmhost', config.builddmain.socket_timeout,
            reactor, proxy)

    def makeCacheFile(self, tachandler, filename):
        """Make a cache file available on the remote subordinate.

        :param tachandler: The TacTestSetup object used to start the remote
            subordinate.
        :param filename: The name of the file to create in the file cache
            area.
        """
        path = os.path.join(tachandler.root, 'filecache', filename)
        fd = open(path, 'w')
        fd.write('something')
        fd.close()
        self.addCleanup(os.unlink, path)

    def triggerGoodBuild(self, subordinate, build_id=None):
        """Trigger a good build on 'subordinate'.

        :param subordinate: A `BuilderSubordinate` instance to trigger the build on.
        :param build_id: The build identifier. If not specified, defaults to
            an arbitrary string.
        :type build_id: str
        :return: The build id returned by the subordinate.
        """
        if build_id is None:
            build_id = 'random-build-id'
        tachandler = self.getServerSubordinate()
        chroot_file = 'fake-chroot'
        dsc_file = 'thing'
        self.makeCacheFile(tachandler, chroot_file)
        self.makeCacheFile(tachandler, dsc_file)
        return subordinate.build(
            build_id, 'debian', chroot_file, {'.dsc': dsc_file},
            {'ogrecomponent': 'main'})
