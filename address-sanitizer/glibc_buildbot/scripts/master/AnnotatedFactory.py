#!/usr/bin/python

import os

import buildbot
import buildbot.process.factory
from buildbot.process.properties import WithProperties
from buildbot.steps.source import SVN
from buildbot.steps.shell import Compile
from buildbot.steps.shell import ShellCommand

from AnnotatedCommand import AnnotatedCommand

def getGlibcAnnotatedFactory(
    clean=False,
    env=None,
    timeout=1200):

    merged_env = {}

    # Use env variables defined in the system.
    merged_env.update(os.environ)
    # Clobber bot if we need a clean build.
    if clean:
        merged_env['BUILDBOT_CLOBBER'] = '1'
    # Overwrite pre-set items with the given ones, so user can set anything.
    if env is not None:
        merged_env.update(env)

    f = buildbot.process.factory.BuildFactory()

    # Determine the build directory.
    f.addStep(buildbot.steps.shell.SetProperty(name='get_builddir',
                                               command=['pwd'],
                                               property='builddir',
                                               description='set build dir',
                                               workdir='.',
                                               env=merged_env))


    # Get buildbot scripts.
    f.addStep(SVN(name='update scripts',
                  mode='update',
                  svnurl='http://address-sanitizer.googlecode.com/svn/trunk/'
                         'glibc_buildbot/scripts',
                  workdir='scripts',
                  alwaysUseLatest=True))

    selector_script = os.path.join('..', 'scripts', 'slave', 'buildbot_selector.py')

    # Run annotated command.
    f.addStep(AnnotatedCommand(name='annotate',
                               description='annotate',
                               timeout=timeout,
                               haltOnFailure=True,
                               command='python ' + selector_script,
                               env=merged_env))
    return f
