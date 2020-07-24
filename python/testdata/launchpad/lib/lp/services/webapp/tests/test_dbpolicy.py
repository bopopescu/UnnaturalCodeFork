# Copyright 2009-2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

"""Tests for the DBPolicy."""

__metaclass__ = type
__all__ = []

from textwrap import dedent
import time

from lazr.restful.interfaces import IWebServiceConfiguration
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from storm.exceptions import DisconnectionError
import transaction
from zope.component import (
    getAdapter,
    getUtility,
    )
from zope.publisher.interfaces.xmlrpc import IXMLRPCRequest
from zope.security.management import (
    endInteraction,
    newInteraction,
    )
from zope.session.interfaces import ISession

from lp.layers import (
    FeedsLayer,
    setFirstLayer,
    WebServiceLayer,
    )
from lp.registry.model.person import Person
from lp.services.config import config
from lp.services.database.interfaces import (
    ALL_STORES,
    DEFAULT_FLAVOR,
    DisallowedStore,
    IDatabasePolicy,
    IMainStore,
    ISubordinateStore,
    IStoreSelector,
    MAIN_STORE,
    MASTER_FLAVOR,
    SLAVE_FLAVOR,
    )
from lp.services.database.policy import (
    BaseDatabasePolicy,
    LaunchpadDatabasePolicy,
    MainDatabasePolicy,
    SubordinateDatabasePolicy,
    SubordinateOnlyDatabasePolicy,
    )
from lp.services.webapp.servers import LaunchpadTestRequest
from lp.testing import TestCase
from lp.testing.fixture import PGBouncerFixture
from lp.testing.layers import (
    DatabaseFunctionalLayer,
    DatabaseLayer,
    FunctionalLayer,
    )


class ImplicitDatabasePolicyTestCase(TestCase):
    """Tests for when there is no policy installed."""
    layer = DatabaseFunctionalLayer

    def test_defaults(self):
        for store in ALL_STORES:
            self.assertProvides(
                getUtility(IStoreSelector).get(store, DEFAULT_FLAVOR),
                IMainStore)

    def test_dbusers(self):
        store_selector = getUtility(IStoreSelector)
        main_store = store_selector.get(MAIN_STORE, DEFAULT_FLAVOR)
        self.failUnlessEqual(self.getDBUser(main_store), 'launchpad_main')

    def getDBUser(self, store):
        return store.execute(
            'SHOW session_authorization').get_one()[0]


class BaseDatabasePolicyTestCase(ImplicitDatabasePolicyTestCase):
    """Base tests for DatabasePolicy implementation."""

    policy = None

    def setUp(self):
        super(BaseDatabasePolicyTestCase, self).setUp()
        if self.policy is None:
            self.policy = BaseDatabasePolicy()
        getUtility(IStoreSelector).push(self.policy)

    def tearDown(self):
        getUtility(IStoreSelector).pop()
        super(BaseDatabasePolicyTestCase, self).tearDown()

    def test_correctly_implements_IDatabasePolicy(self):
        self.assertProvides(self.policy, IDatabasePolicy)


class SubordinateDatabasePolicyTestCase(BaseDatabasePolicyTestCase):
    """Tests for the `SubordinateDatabasePolicy`."""

    def setUp(self):
        if self.policy is None:
            self.policy = SubordinateDatabasePolicy()
        super(SubordinateDatabasePolicyTestCase, self).setUp()

    def test_defaults(self):
        for store in ALL_STORES:
            self.assertProvides(
                getUtility(IStoreSelector).get(store, DEFAULT_FLAVOR),
                ISubordinateStore)

    def test_main_allowed(self):
        for store in ALL_STORES:
            self.assertProvides(
                getUtility(IStoreSelector).get(store, MASTER_FLAVOR),
                IMainStore)


class SubordinateOnlyDatabasePolicyTestCase(SubordinateDatabasePolicyTestCase):
    """Tests for the `SubordinateDatabasePolicy`."""

    def setUp(self):
        self.policy = SubordinateOnlyDatabasePolicy()
        super(SubordinateOnlyDatabasePolicyTestCase, self).setUp()

    def test_main_allowed(self):
        for store in ALL_STORES:
            self.failUnlessRaises(
                DisallowedStore,
                getUtility(IStoreSelector).get, store, MASTER_FLAVOR)


class MainDatabasePolicyTestCase(BaseDatabasePolicyTestCase):
    """Tests for the `MainDatabasePolicy`."""

    def setUp(self):
        self.policy = MainDatabasePolicy()
        super(MainDatabasePolicyTestCase, self).setUp()

    def test_XMLRPCRequest_uses_MainPolicy(self):
        """XMLRPC should always use the main flavor, since they always
        use POST and do not support session cookies.
        """
        request = LaunchpadTestRequest(
            SERVER_URL='http://xmlrpc-private.launchpad.dev')
        setFirstLayer(request, IXMLRPCRequest)
        policy = getAdapter(request, IDatabasePolicy)
        self.failUnless(
            isinstance(policy, MainDatabasePolicy),
            "Expected MainDatabasePolicy, not %s." % policy)

    def test_subordinate_allowed(self):
        # We get the main store even if the subordinate was requested.
        for store in ALL_STORES:
            self.assertProvides(
                getUtility(IStoreSelector).get(store, SLAVE_FLAVOR),
                ISubordinateStore)


class LaunchpadDatabasePolicyTestCase(SubordinateDatabasePolicyTestCase):
    """Fuller LaunchpadDatabasePolicy tests are in the page tests.

    This test just checks the defaults, which is the same as the
    subordinate policy for unauthenticated requests.
    """

    def setUp(self):
        request = LaunchpadTestRequest(SERVER_URL='http://launchpad.dev')
        self.policy = LaunchpadDatabasePolicy(request)
        super(LaunchpadDatabasePolicyTestCase, self).setUp()


class LayerDatabasePolicyTestCase(TestCase):
    layer = FunctionalLayer

    def test_FeedsLayer_uses_SubordinateDatabasePolicy(self):
        """FeedsRequest should use the SubordinateDatabasePolicy since they
        are read-only in nature. Also we don't want to send session cookies
        over them.
        """
        request = LaunchpadTestRequest(
            SERVER_URL='http://feeds.launchpad.dev')
        setFirstLayer(request, FeedsLayer)
        policy = IDatabasePolicy(request)
        self.assertIsInstance(policy, SubordinateOnlyDatabasePolicy)

    def test_WebServiceRequest_uses_MainDatabasePolicy(self):
        """WebService requests should always use the main flavor, since
        it's likely that clients won't support cookies and thus mixing read
        and write requests will result in incoherent views of the data.

        XXX 20090320 Stuart Bishop bug=297052: This doesn't scale of course
            and will meltdown when the API becomes popular.
        """
        api_prefix = getUtility(
            IWebServiceConfiguration).active_versions[0]
        server_url = 'http://api.launchpad.dev/%s' % api_prefix
        request = LaunchpadTestRequest(SERVER_URL=server_url)
        setFirstLayer(request, WebServiceLayer)
        policy = IDatabasePolicy(request)
        self.assertIsInstance(policy, MainDatabasePolicy)

    def test_WebServiceRequest_uses_LaunchpadDatabasePolicy(self):
        """WebService requests with a session cookie will use the
        standard LaunchpadDatabasePolicy so their database queries
        can be outsourced to a subordinate database when possible.
        """
        api_prefix = getUtility(
            IWebServiceConfiguration).active_versions[0]
        server_url = 'http://api.launchpad.dev/%s' % api_prefix
        request = LaunchpadTestRequest(SERVER_URL=server_url)
        newInteraction(request)
        try:
            # First, generate a valid session cookie.
            ISession(request)['whatever']['whatever'] = 'whatever'
            # Then stuff it into the request where we expect to
            # find it. The database policy is only interested if
            # a session cookie was sent with the request, not it
            # one has subsequently been set in the response.
            request._cookies = request.response._cookies
            setFirstLayer(request, WebServiceLayer)
            policy = IDatabasePolicy(request)
            self.assertIsInstance(policy, LaunchpadDatabasePolicy)
        finally:
            endInteraction()

    def test_other_request_uses_LaunchpadDatabasePolicy(self):
        """By default, requests should use the LaunchpadDatabasePolicy."""
        server_url = 'http://launchpad.dev/'
        request = LaunchpadTestRequest(SERVER_URL=server_url)
        policy = IDatabasePolicy(request)
        self.assertIsInstance(policy, LaunchpadDatabasePolicy)


class MainFallbackTestCase(TestCase):
    layer = DatabaseFunctionalLayer

    def setUp(self):
        super(MainFallbackTestCase, self).setUp()

        self.pgbouncer_fixture = PGBouncerFixture()

        # The PGBouncerFixture will set the PGPORT environment variable,
        # causing all DB connections to go via pgbouncer unless an
        # explicit port is provided.
        dbname = DatabaseLayer._db_fixture.dbname
        # Pull the direct db connection string, including explicit port.
        conn_str_direct = self.pgbouncer_fixture.databases[dbname]
        # Generate a db connection string that will go via pgbouncer.
        conn_str_pgbouncer = 'dbname=%s host=localhost' % dbname

        # Configure subordinate connections via pgbouncer, so we can shut them
        # down. Main connections direct so they are unaffected.
        config_key = 'main-subordinate-separation'
        config.push(config_key, dedent('''\
            [database]
            rw_main_main: %s
            rw_main_subordinate: %s
            ''' % (conn_str_direct, conn_str_pgbouncer)))
        self.addCleanup(lambda: config.pop(config_key))

        self.useFixture(self.pgbouncer_fixture)

    def test_can_shutdown_subordinate_only(self):
        '''Confirm that this TestCase's test infrastructure works as needed.
        '''
        main_store = IMainStore(Person)
        subordinate_store = ISubordinateStore(Person)

        # Both Stores work when pgbouncer is up.
        main_store.get(Person, 1)
        subordinate_store.get(Person, 1)

        # Subordinate Store breaks when pgbouncer is torn down. Main Store
        # is fine.
        self.pgbouncer_fixture.stop()
        main_store.get(Person, 2)
        self.assertRaises(DisconnectionError, subordinate_store.get, Person, 2)

    def test_startup_with_no_subordinate(self):
        '''An attempt is made for the first time to connect to a subordinate.'''
        self.pgbouncer_fixture.stop()

        main_store = IMainStore(Person)
        subordinate_store = ISubordinateStore(Person)

        # The main and subordinate Stores are the same object.
        self.assertIs(main_store, subordinate_store)

    def test_subordinate_shutdown_during_transaction(self):
        '''Subordinate is shutdown while running, but we can recover.'''
        main_store = IMainStore(Person)
        subordinate_store = ISubordinateStore(Person)

        self.assertIsNot(main_store, subordinate_store)

        self.pgbouncer_fixture.stop()

        # The transaction fails if the subordinate store is used. Robust
        # processes will handle this and retry (even if just means exit
        # and wait for the next scheduled invocation).
        self.assertRaises(DisconnectionError, subordinate_store.get, Person, 1)

        transaction.abort()

        # But in the next transaction, we get the main Store if we ask
        # for the subordinate Store so we can continue.
        main_store = IMainStore(Person)
        subordinate_store = ISubordinateStore(Person)

        self.assertIs(main_store, subordinate_store)

    def test_subordinate_shutdown_between_transactions(self):
        '''Subordinate is shutdown in between transactions.'''
        main_store = IMainStore(Person)
        subordinate_store = ISubordinateStore(Person)
        self.assertIsNot(main_store, subordinate_store)

        transaction.abort()
        self.pgbouncer_fixture.stop()

        # The process doesn't notice the subordinate going down, and things
        # will fail the next time the subordinate is used.
        main_store = IMainStore(Person)
        subordinate_store = ISubordinateStore(Person)
        self.assertIsNot(main_store, subordinate_store)
        self.assertRaises(DisconnectionError, subordinate_store.get, Person, 1)

        # But now it has been discovered the socket is no longer
        # connected to anything, next transaction we get a main
        # Store when we ask for a subordinate.
        main_store = IMainStore(Person)
        subordinate_store = ISubordinateStore(Person)
        self.assertIs(main_store, subordinate_store)

    def test_subordinate_reconnect_after_outage(self):
        '''The subordinate is again used once it becomes available.'''
        self.pgbouncer_fixture.stop()

        main_store = IMainStore(Person)
        subordinate_store = ISubordinateStore(Person)
        self.assertIs(main_store, subordinate_store)

        self.pgbouncer_fixture.start()
        transaction.abort()

        main_store = IMainStore(Person)
        subordinate_store = ISubordinateStore(Person)
        self.assertIsNot(main_store, subordinate_store)


class TestFastDowntimeRollout(TestCase):
    layer = DatabaseFunctionalLayer

    def setUp(self):
        super(TestFastDowntimeRollout, self).setUp()

        self.main_dbname = DatabaseLayer._db_fixture.dbname
        self.subordinate_dbname = self.main_dbname + '_subordinate'

        self.pgbouncer_fixture = PGBouncerFixture()
        self.pgbouncer_fixture.databases[self.subordinate_dbname] = (
            self.pgbouncer_fixture.databases[self.main_dbname])

        # Configure main and subordinate connections to go via different
        # pgbouncer aliases.
        config_key = 'main-subordinate-separation'
        config.push(config_key, dedent('''\
            [database]
            rw_main_main: dbname=%s host=localhost
            rw_main_subordinate: dbname=%s host=localhost
            ''' % (self.main_dbname, self.subordinate_dbname)))
        self.addCleanup(lambda: config.pop(config_key))

        self.useFixture(self.pgbouncer_fixture)

        self.pgbouncer_con = psycopg2.connect(
            'dbname=pgbouncer user=pgbouncer host=localhost')
        self.pgbouncer_con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        self.pgbouncer_cur = self.pgbouncer_con.cursor()

        transaction.abort()

    def store_is_working(self, store):
        try:
            store.execute('SELECT TRUE')
            return True
        except DisconnectionError:
            return False

    def store_is_subordinate(self, store):
        return store.get_database().name == 'main-subordinate'

    def store_is_main(self, store):
        return not self.store_is_subordinate(store)

    def wait_until_connectable(self, dbname):
        timeout = 80
        start = time.time()
        while time.time() < start + timeout:
            try:
                con = psycopg2.connect(
                    'dbname=%s host=localhost user=launchpad_main' % dbname)
                con.cursor().execute('SELECT TRUE')
                con.close()
                return
            except psycopg2.Error:
                pass
            time.sleep(0.2)
        self.fail("Unable to resume database %s" % dbname)

    def test_subordinate_only_fast_downtime_rollout(self):
        '''You can always access a working subordinate store during fast downtime.
        '''
        # Everything is running happily.
        store = ISubordinateStore(Person)
        original_store = store
        self.assertTrue(self.store_is_working(store))
        self.assertTrue(self.store_is_subordinate(store))

        # But fast downtime is about to happen.

        # Replication is stopped on the subordinate, and lag starts
        # increasing.

        # All connections to the main are killed so database schema
        # updates can be applied.
        self.pgbouncer_cur.execute('DISABLE %s' % self.main_dbname)
        self.pgbouncer_cur.execute('KILL %s' % self.main_dbname)

        # Of course, subordinate connections are unaffected.
        self.assertTrue(self.store_is_working(store))

        # After schema updates have been made to the main, it is
        # reenabled.
        self.pgbouncer_cur.execute('RESUME %s' % self.main_dbname)
        self.pgbouncer_cur.execute('ENABLE %s' % self.main_dbname)

        # And the subordinates taken down, and replication reenabled so the
        # schema updates can replicate.
        self.pgbouncer_cur.execute('DISABLE %s' % self.subordinate_dbname)
        self.pgbouncer_cur.execute('KILL %s' % self.subordinate_dbname)

        # The next attempt at accessing the subordinate store will fail
        # with a DisconnectionError.
        self.assertRaises(DisconnectionError, store.execute, 'SELECT TRUE')
        transaction.abort()

        # But if we handle that and retry, we can continue.
        # Now the failed connection has been detected, the next Store
        # we are handed is a main Store instead of a subordinate.
        store = ISubordinateStore(Person)
        self.assertTrue(self.store_is_main(store))
        self.assertIsNot(ISubordinateStore(Person), original_store)

        # But alas, it might not work the first transaction. If it has
        # been earlier, its connection was killed by pgbouncer earlier
        # but it hasn't noticed yet.
        self.assertFalse(self.store_is_working(store))
        transaction.abort()

        # Next retry attempt, everything is fine using the main
        # connection, even though our code only asked for a subordinate.
        store = ISubordinateStore(Person)
        self.assertTrue(self.store_is_main(store))
        self.assertTrue(self.store_is_working(store))

        # The original Store is busted though. You cannot reuse Stores
        # across transaction bounderies because you might end up using
        # the wrong Store.
        self.assertFalse(self.store_is_working(original_store))
        transaction.abort()

        # Once replication has caught up, the subordinate is reenabled.
        self.pgbouncer_cur.execute('RESUME %s' % self.subordinate_dbname)
        self.pgbouncer_cur.execute('ENABLE %s' % self.subordinate_dbname)

        # And next transaction, we are back to normal.
        store = ISubordinateStore(Person)
        self.assertTrue(self.store_is_working(store))
        self.assertTrue(self.store_is_subordinate(store))
        self.assertIs(original_store, store)

    def test_main_subordinate_fast_downtime_rollout(self):
        '''Parts of your app can keep working during a fast downtime update.
        '''
        # Everything is running happily.
        main_store = IMainStore(Person)
        self.assertTrue(self.store_is_main(main_store))
        self.assertTrue(self.store_is_working(main_store))

        subordinate_store = ISubordinateStore(Person)
        self.assertTrue(self.store_is_subordinate(subordinate_store))
        self.assertTrue(self.store_is_working(subordinate_store))

        # But fast downtime is about to happen.

        # Replication is stopped on the subordinate, and lag starts
        # increasing.

        # All connections to the main are killed so database schema
        # updates can be applied.
        self.pgbouncer_cur.execute('DISABLE %s' % self.main_dbname)
        self.pgbouncer_cur.execute('KILL %s' % self.main_dbname)

        # Of course, subordinate connections are unaffected.
        self.assertTrue(self.store_is_working(subordinate_store))

        # But attempts to use a main store will fail.
        self.assertFalse(self.store_is_working(main_store))
        transaction.abort()

        # After schema updates have been made to the main, it is
        # reenabled.
        self.pgbouncer_cur.execute('RESUME %s' % self.main_dbname)
        self.pgbouncer_cur.execute('ENABLE %s' % self.main_dbname)

        # And the subordinates taken down, and replication reenabled so the
        # schema updates can replicate.
        self.pgbouncer_cur.execute('DISABLE %s' % self.subordinate_dbname)
        self.pgbouncer_cur.execute('KILL %s' % self.subordinate_dbname)

        # The main store is working again.
        main_store = IMainStore(Person)
        self.assertTrue(self.store_is_main(main_store))
        self.assertTrue(self.store_is_working(main_store))

        # The next attempt at accessing the subordinate store will fail
        # with a DisconnectionError.
        subordinate_store = ISubordinateStore(Person)
        self.assertTrue(self.store_is_subordinate(subordinate_store))
        self.assertRaises(
            DisconnectionError, subordinate_store.execute, 'SELECT TRUE')
        transaction.abort()

        # But if we handle that and retry, we can continue.
        # Now the failed connection has been detected, the next Store
        # we are handed is a main Store instead of a subordinate.
        subordinate_store = ISubordinateStore(Person)
        self.assertTrue(self.store_is_main(subordinate_store))
        self.assertTrue(self.store_is_working(subordinate_store))

        # Once replication has caught up, the subordinate is reenabled.
        self.pgbouncer_cur.execute('RESUME %s' % self.subordinate_dbname)
        self.pgbouncer_cur.execute('ENABLE %s' % self.subordinate_dbname)

        # And next transaction, we are back to normal.
        transaction.abort()
        main_store = IMainStore(Person)
        self.assertTrue(self.store_is_main(main_store))
        self.assertTrue(self.store_is_working(main_store))

        subordinate_store = ISubordinateStore(Person)
        self.assertTrue(self.store_is_subordinate(subordinate_store))
        self.assertTrue(self.store_is_working(subordinate_store))
