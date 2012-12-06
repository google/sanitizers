#!/usr/bin/python

from buildbot.process import factory
from buildbot.steps.source import SVN
from buildbot.steps.shell import Compile
from buildbot.steps.shell import ShellCommand

import chromium_step
import masterutil

f1 = factory.BuildFactory()

f1.addStep(ShellCommand(command='svn cleanup ../../../scripts',
                        timeout=60,
                        name='cleanup scripts',
                        description='cleanup scripts'))

svn_flags = '--non-interactive --trust-server-cert'
f1.addStep(ShellCommand(command='svn up ../../../scripts %s' % svn_flags,
                        timeout=60,
                        name='update scripts',
                        description='update scripts'))

f1.addStep(chromium_step.AnnotatedCommand,
           name='annotate',
           description='annotate',
           timeout=1200,
           haltOnFailure=True,
           command='python ../../../scripts/slave/buildbot_selector.py')
