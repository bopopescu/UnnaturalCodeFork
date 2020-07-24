# Copyright 2009-2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

"""Interface for build farm job behaviors."""

__metaclass__ = type

__all__ = [
    'IBuildFarmJobBehavior',
    ]

from zope.interface import Interface


class IBuildFarmJobBehavior(Interface):

    def setBuilder(builder, subordinate):
        """Sets the associated builder and subordinate for this instance."""

    def logStartBuild(logger):
        """Log the start of a specific build queue item.

        The form of the log message will vary depending on the type of build.
        :param build_queue_item: A BuildQueueItem to build.
        :param logger: A logger to be used to log diagnostic information.
        """

    def dispatchBuildToSubordinate(build_queue_item_id, logger):
        """Dispatch a specific build to the subordinate.

        :param build_queue_item_id: An identifier for the build queue item.
        :param logger: A logger to be used to log diagnostic information.
        """

    def verifyBuildRequest(logger):
        """Carry out any pre-build checks.

        :param logger: A logger to be used to log diagnostic information.
        """

    def getBuildCookie():
        """Return a string which uniquely identifies the job."""

    def updateSubordinateStatus(status_sentence, status_dict):
        """Update the subordinate status dict with custom values for this behavior.

        :param status_sentence: The value returned by the build subordinate's
           status() method.
        :param status_dict: A dict of the processed subordinate status values
           provided by all types: builder_status, build_id, and optionally
           build_status or logtail. This should have any behaviour-specific
           values added to it.
        """

    def handleStatus(bq, status, status_dict):
        """Update the build from a WAITING subordinate result.

        :param bq: The `BuildQueue` currently being processed.
        :param status: The tail of the BuildStatus (eg. OK or PACKAGEFAIL).
        :param status_dict: Subordinate status dict from
           `BuilderInteractor.subordinateStatus` and `updateSubordinateStatus`.
        """
