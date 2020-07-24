# Copyright 2011 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

"""Session adapters."""

__metaclass__ = type
__all__ = []


from zope.component import adapter
from zope.interface import implementer

from lp.services.database.interfaces import (
    IMainStore,
    ISubordinateStore,
    IStore,
    )
from lp.services.database.sqlbase import session_store
from lp.services.session.interfaces import IUseSessionStore


@adapter(IUseSessionStore)
@implementer(IMainStore)
def session_main_store(cls):
    """Adapt a Session database object to an `IMainStore`."""
    return session_store()


@adapter(IUseSessionStore)
@implementer(ISubordinateStore)
def session_subordinate_store(cls):
    """Adapt a Session database object to an `ISubordinateStore`."""
    return session_store()


@adapter(IUseSessionStore)
@implementer(IStore)
def session_default_store(cls):
    """Adapt an Session database object to an `IStore`."""
    return session_store()
