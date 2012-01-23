#!/usr/bin/python

from buildbot.process import factory
from buildbot.steps.source import SVN
from buildbot.steps.shell import Compile
from buildbot.steps.shell import ShellCommand

import chromium_step
import masterutil

f1 = factory.BuildFactory()

f1.addStep(ShellCommand(command='svn up ../../../scripts',
                        timeout=60,
                        name='update scripts'))

f1.addStep(chromium_step.AnnotatedCommand,
           name='annotate',
           description='annotate',
           timeout=1200,
           haltOnFailure=True,
           command='../../../scripts/slave/buildbot_selector.py')
