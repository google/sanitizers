# Copyright (c) 2011 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Subclasses of various slave command classes."""

import copy
import re
import time


from buildbot import util
from buildbot.process import buildstep
from buildbot.process.properties import WithProperties
from buildbot.status import builder
from buildbot.steps import shell
from buildbot.steps import source


class GClient(source.Source):
  """Check out a source tree using gclient."""

  name = 'update'

  def __init__(self, svnurl=None, rm_timeout=None, gclient_spec=None, env=None,
               sudo_for_remove=False, gclient_deps=None, gclient_nohooks=False,
               no_gclient_branch=False, **kwargs):
    source.Source.__init__(self, **kwargs)
    if env:
      self.args['env'] = env.copy()
    self.args['rm_timeout'] = rm_timeout
    self.args['svnurl'] = svnurl
    self.args['sudo_for_remove'] = sudo_for_remove
    # linux doesn't handle spaces in command line args properly so remove them.
    # This doesn't matter for the format of the DEPS file.
    self.args['gclient_spec'] = gclient_spec.replace(' ', '')
    self.args['gclient_deps'] = gclient_deps
    self.args['gclient_nohooks'] = gclient_nohooks
    self.args['no_gclient_branch'] = no_gclient_branch

  def computeSourceRevision(self, changes):
    """Finds the latest revision number from the changeset that have
    triggered the build.

    This is a hook method provided by the parent source.Source class and
    default implementation in source.Source returns None. Return value of this
    method is be used to set 'revsion' argument value for startVC() method."""
    if not changes:
      return None
    def GrabRevision(c):
      """Handle revision == None or any invalid value."""
      try:
        return int(c.revision)
      except TypeError:
        return 0
    # Change revision numbers can be invalid, for a try job for instance.
    lastChange = max([GrabRevision(c) for c in changes])
    return lastChange

  def startVC(self, branch, revision, patch):
    warnings = []
    args = copy.copy(self.args)
    args['revision'] = revision
    args['branch'] = branch
    if args.get('gclient_spec'):
      args['gclient_spec'] = args['gclient_spec'].replace('$$WK_REV$$',
                                                          str(revision or ''))
    if patch:
      args['patch'] = patch
    elif args.get('patch') is None:
      del args['patch']
    cmd = buildstep.LoggedRemoteCommand('gclient', args)
    self.startCommand(cmd, warnings)

  def describe(self, done=False):
    """Tries to append the revision number to the description."""
    description = source.Source.describe(self, done)
    self.appendRevision(description)
    self.appendWebKitRevision(description)
    return description

  def appendRevision(self, description):
    """Tries to append the Chromium revision to the given description."""
    revision = None
    try:
      revision = self.getProperty('got_revision')
    except KeyError:
      # 'got_revision' doesn't exist yet, check 'revision'
      try:
        revision = self.getProperty('revision')
      except KeyError:
        pass  # neither exist, go on without revision
    if revision:
      revision = 'r%s' % revision
      # Only append revision if it's not already there.
      if not revision in description:
        description.append(revision)

  def appendWebKitRevision(self, description):
    """Tries to append the WebKit revision to the given description."""
    webkit_revision = None
    try:
      webkit_revision = self.getProperty('got_webkit_revision')
    except KeyError:
      pass
    if webkit_revision:
      webkit_revision = 'webkit r%s' % webkit_revision
      # Only append revision if it's not already there.
      if not webkit_revision in description:
        description.append(webkit_revision)

  def commandComplete(self, cmd):
    """Handles status updates from buildbot slave when the step is done.

    As a result both 'got_revision' and 'got_webkit_revision' properties will
    be set, though either may be None if it couldn't be found.
    """
    source.Source.commandComplete(self, cmd)
    if cmd.updates.has_key('got_webkit_revision'):
      got_webkit_revision = cmd.updates['got_webkit_revision'][-1]
      if got_webkit_revision:
        self.setProperty('got_webkit_revision', str(got_webkit_revision),
                         'Source')


class BuilderStatus(object):
  # Order in asceding severity.
  BUILD_STATUS_ORDERING = [
      builder.SUCCESS,
      builder.WARNINGS,
      builder.FAILURE,
      builder.EXCEPTION,
  ]

  @classmethod
  def combine(cls, a, b):
    """Combine two status, favoring the more severe."""
    if a not in cls.BUILD_STATUS_ORDERING:
      return b
    if b not in cls.BUILD_STATUS_ORDERING:
      return a
    a_rank = cls.BUILD_STATUS_ORDERING.index(a)
    b_rank = cls.BUILD_STATUS_ORDERING.index(b)
    pick = max(a_rank, b_rank)
    return cls.BUILD_STATUS_ORDERING[pick]


class ProcessLogShellStep(shell.ShellCommand):
  """ Step that can process log files.

    Delegates actual processing to log_processor, which is a subclass of
    process_log.PerformanceLogParser.

    Sample usage:
    # construct class that will have no-arg constructor.
    log_processor_class = chromium_utils.PartiallyInitialize(
        process_log.GraphingPageCyclerLogProcessor,
        report_link='http://host:8010/report.html,
        output_dir='~/www')
    # We are partially constructing Step because the step final
    # initialization is done by BuildBot.
    step = chromium_utils.PartiallyInitialize(
        chromium_step.ProcessLogShellStep,
        log_processor_class)

  """
  def  __init__(self, log_processor_class=None, *args, **kwargs):
    """
    Args:
      log_processor_class: subclass of
        process_log.PerformanceLogProcessor that will be initialized and
        invoked once command was successfully completed.
    """
    self._result_text = []
    self._log_processor = None
    # If log_processor_class is not None, it should be a class.  Create an
    # instance of it.
    if log_processor_class:
      self._log_processor = log_processor_class()
    shell.ShellCommand.__init__(self, *args, **kwargs)

  def start(self):
    """Overridden shell.ShellCommand.start method.

    Adds a link for the activity that points to report ULR.
    """
    self._CreateReportLinkIfNeccessary()
    shell.ShellCommand.start(self)

  def _GetRevision(self):
    """Returns the revision number for the build.

    Result is the revision number of the latest change that went in
    while doing gclient sync. Tries 'got_revision' (from log parsing)
    then tries 'revision' (usually from forced build). If neither are
    found, will return -1 instead.
    """
    revision = None
    try:
      revision = self.build.getProperty('got_revision')
    except KeyError:
      pass  # 'got_revision' doesn't exist (yet)
    if not revision:
      try:
        revision = self.build.getProperty('revision')
      except KeyError:
        pass  # neither exist
    if not revision:
      revision = -1
    return revision

  def commandComplete(self, cmd):
    """Callback implementation that will use log process to parse 'stdio' data.
    """
    if self._log_processor:
      self._result_text = self._log_processor.Process(
          self._GetRevision(), self.getLog('stdio').getText())

  def getText(self, cmd, results):
    text_list = self.describe(True)
    if self._result_text:
      self._result_text.insert(0, '<div class="BuildResultInfo">')
      self._result_text.append('</div>')
      text_list = text_list + self._result_text
    return text_list

  def evaluateCommand(self, cmd):
    shell_result = shell.ShellCommand.evaluateCommand(self, cmd)
    log_result = None
    if self._log_processor and 'evaluateCommand' in dir(self._log_processor):
      log_result = self._log_processor.evaluateCommand(cmd)
    return BuilderStatus.combine(shell_result, log_result)

  def _CreateReportLinkIfNeccessary(self):
    if self._log_processor and self._log_processor.ReportLink():
      self.addURL('results', "%s" % self._log_processor.ReportLink())


class AnnotationObserver(buildstep.LogLineObserver):
  """This class knows how to understand annotations.

  Here are a list of the currently supported annotations:

  @@@BUILD_STEP <stepname>@@@
  Add a new step <stepname>. End the current step, marking with last available
  status.

  @@@STEP_LINK@<label>@<url>@@@
  Add a link with label <label> linking to <url> to the current stage.

  @@@STEP_WARNINGS@@@
  Mark the current step as having warnings (oragnge).

  @@@STEP_FAILURE@@@
  Mark the current step as having failed (red).

  @@@STEP_EXCEPTION@@@
  Mark the current step as having exceptions (magenta).

  @@@STEP_CLEAR@@@
  Reset the text description of the current step.

  @@@STEP_SUMMARY_CLEAR@@@
  Reset the text summary of the current step.

  @@@STEP_TEXT@<msg>@@@
  Append <msg> to the current step text.

  @@@STEP_SUMMARY_TEXT@<msg>@@@
  Append <msg> to the step summary (appears on top of the waterfall).

  @@@HALT_ON_FAILURE@@@
  Halt if exception or failure steps are encountered (default is not).

  @@@HONOR_ZERO_RETURN_CODE@@@
  Honor the return code being zero (success), even if steps have other results.

  Deprecated annotations:
  TODO(bradnelson): drop these when all users have been tracked down.

  @@@BUILD_WARNINGS@@@
  Equivalent to @@@STEP_WARNINGS@@@

  @@@BUILD_FAILED@@@
  Equivalent to @@@STEP_FAILURE@@@

  @@@BUILD_EXCEPTION@@@
  Equivalent to @@@STEP_EXCEPTION@@@

  @@@link@<label>@<url>@@@
  Equivalent to @@@STEP_LINK@<label>@<url>@@@
  """

  def __init__(self, command=None, *args, **kwargs):
    buildstep.LogLineObserver.__init__(self, *args, **kwargs)
    self.command = command
    self.sections = []
    self.annotate_status = builder.SUCCESS
    self.halt_on_failure = False
    self.honor_zero_return_code = False

  def initialSection(self):
    if self.sections:
      return
    # Add a log section for output before the first section heading.
    log = self.command.addLog('preamble')
    self.sections.append({
        'name': 'preamble',
        'step': self.command.step_status.getBuild().steps[-1],
        'log': log,
        'status': builder.SUCCESS,
        'links': [],
        'step_summary_text': [],
        'step_text': [],
    })

  def fixupLast(self, status=None):
    # Potentially start initial section here, as initial section might have
    # no output at all.
    self.initialSection()

    last = self.sections[-1]
    # Update status if set as an argument.
    if status is not None:
      last['status'] = status
    # Final update of text.
    self.updateText()
    # Add timing info.
    (start, end) = self.command.step_status.getTimes()
    msg = '\n\n' + '-' * 80 + '\n'
    if start is None:
      msg += 'Not Started\n'
    else:
      if end is None:
        end = util.now()
      msg += '\n'.join([
          'started: %s' % time.ctime(start),
          'ended: %s' % time.ctime(end),
          'duration: %s' % util.formatInterval(end - start),
          '',  # So we get a final \n
      ])
    last['log'].addStdout(msg)
    # Change status (unless handling the preamble).
    if len(self.sections) != 1:
      last['step'].stepFinished(last['status'])
    # Finish log.
    last['log'].finish()

  def errLineReceived(self, line):
    self.outLineReceived(line)

  def updateStepStatus(self, status):
    """Update current step status and annotation status based on a new event."""
    self.annotate_status = BuilderStatus.combine(self.annotate_status, status)
    last = self.sections[-1]
    last['status'] = BuilderStatus.combine(last['status'], status)
    if self.halt_on_failure and last['status'] in [
        builder.FAILURE, builder.EXCEPTION]:
      self.fixupLast()
      self.command.finished(last['status'])

  def updateText(self):
    # Don't update the main phase's text.
    if len(self.sections) == 1:
      return

    last = self.sections[-1]

    # Reflect step status in text2.
    if last['status'] == builder.EXCEPTION:
      result = ['exception', last['name']]
    elif last['status'] == builder.FAILURE:
      result = ['failed', last['name']]
    else:
      result = []

    last['step'].setText([last['name']] + last['step_text'])
    last['step'].setText2(result + last['step_summary_text'])

  def outLineReceived(self, line):
    """This is called once with each line of the test log."""
    # Add \n if not there, which seems to be the case for log lines from
    # windows agents, but not others.
    if not line.endswith('\n'):
      line += '\n'
    # Handle initial setup here, as step_status might not exist yet at init.
    self.initialSection()
    # Support: @@@STEP_LINK@<name>@<url>@@@ (emit link)
    # Also support depreceated @@@link@<name>@<url>@@@
    m = re.match('^@@@STEP_LINK@(.*)@(.*)@@@', line)
    if not m:
      m = re.match('^@@@link@(.*)@(.*)@@@', line)
    if m:
      link_label = m.group(1)
      link_url = m.group(2)
      self.sections[-1]['links'].append((link_label, link_url))
      self.sections[-1]['step'].addURL(link_label, link_url)
    # Support: @@@STEP_WARNINGS@@@ (warn on a stage)
    # Also support deprecated @@@BUILD_WARNINGS@@@
    if (line.startswith('@@@STEP_WARNINGS@@@') or
        line.startswith('@@@BUILD_WARNINGS@@@')):
      self.updateStepStatus(builder.WARNINGS)
    # Support: @@@STEP_FAILURE@@@ (fail a stage)
    # Also support deprecated @@@BUILD_FAILED@@@
    if (line.startswith('@@@STEP_FAILURE@@@') or
        line.startswith('@@@BUILD_FAILED@@@')):
      self.updateStepStatus(builder.FAILURE)
    # Support: @@@STEP_EXCEPTION@@@ (exception on a stage)
    # Also support deprecated @@@BUILD_FAILED@@@
    if (line.startswith('@@@STEP_EXCEPTION@@@') or
        line.startswith('@@@BUILD_EXCEPTION@@@')):
      self.updateStepStatus(builder.EXCEPTION)
    # Support: @@@HALT_ON_FAILURE@@@ (halt if a step fails immediately)
    if line.startswith('@@@HALT_ON_FAILURE@@@'):
      self.halt_on_failure = True
    # Support: @@@HONOR_ZERO_RETURN_CODE@@@ (succeed on 0 return, even if some
    #     steps have failed)
    if line.startswith('@@@HONOR_ZERO_RETURN_CODE@@@'):
      self.honor_zero_return_code = True
    # Support: @@@STEP_CLEAR@@@ (reset step description)
    if line.startswith('@@@STEP_CLEAR@@@'):
      self.sections[-1]['step_text'] = []
      self.updateText()
    # Support: @@@STEP_SUMMARY_CLEAR@@@ (reset step summary)
    if line.startswith('@@@STEP_SUMMARY_CLEAR@@@'):
      self.sections[-1]['step_summary_text'] = []
      self.updateText()
    # Support: @@@STEP_TEXT@<msg>@@@
    m = re.match('^@@@STEP_TEXT@(.*)@@@', line)
    if m:
      self.sections[-1]['step_text'].append(m.group(1))
      self.updateText()
    # Support: @@@STEP_SUMMARY_TEXT@<msg>@@@
    m = re.match('^@@@STEP_SUMMARY_TEXT@(.*)@@@', line)
    if m:
      self.sections[-1]['step_summary_text'].append(m.group(1))
      self.updateText()
    # Support: @@@BUILD_STEP <step_name>@@@ (start a new section)
    m = re.match('^@@@BUILD_STEP (.*)@@@', line)
    if m:
      step_name = m.group(1)
      # Ignore duplicate consecutive step labels (for robustness).
      if step_name != self.sections[-1]['name']:
        # Finish up last section.
        self.fixupLast()
        # Add new one.
        step = self.command.step_status.getBuild().addStepWithName(step_name)
        step.stepStarted()
        step.setText([step_name])
        log = step.addLog('stdio')
        self.sections.append({
            'name': step_name,
            'step': step,
            'log': log,
            'status': builder.SUCCESS,
            'links': [],
            'step_summary_text': [],
            'step_text': [],
        })
    # Add to the current secondary log.
    # Doing this last so that @@@BUILD_STEP... occurs in the log of the new
    # step.
    self.sections[-1]['log'].addStdout(line)

  def handleReturnCode(self, return_code):
    # Treat all non-zero return codes as failure.
    # We could have a special return code for warnings/exceptions, however,
    # this might conflict with some existing use of a return code.
    # Besides, applications can always intercept return codes and emit
    # STEP_* tags.
    if return_code == 0:
      self.fixupLast()
      if self.honor_zero_return_code:
        self.annotate_status = builder.SUCCESS
    else:
      self.annotate_status = builder.FAILURE
      self.fixupLast(builder.FAILURE)


class AnnotatedCommand(ProcessLogShellStep):
  """Buildbot command that knows how to display annotations."""

  def __init__(self, *args, **kwargs):
    # Inject standard tags into the environment.
    env = {
        'BUILDBOT_BLAMELIST': WithProperties('%(blamelist:-[])s'),
        'BUILDBOT_BRANCH': WithProperties('%(branch:-None)s'),
        'BUILDBOT_BUILDERNAME': WithProperties('%(buildername:-None)s'),
        'BUILDBOT_BUILDNUMBER': WithProperties('%(buildnumber:-None)s'),
        'BUILDBOT_CLOBBER': WithProperties('%(clobber:+1)s'),
        'BUILDBOT_GOT_REVISION': WithProperties('%(got_revision:-None)s'),
        'BUILDBOT_REVISION': WithProperties('%(revision:-None)s'),
        'BUILDBOT_SCHEDULER': WithProperties('%(scheduler:-None)s'),
        'BUILDBOT_SLAVENAME': WithProperties('%(slavename:-None)s'),
    }
    # Apply the passed in environment on top.
    old_env = kwargs.get('env')
    if not old_env:
      old_env = {}
    env.update(old_env)
    # Change passed in args (ok as a copy is made internally).
    kwargs['env'] = env

    ProcessLogShellStep.__init__(self, *args, **kwargs)
    self.script_observer = AnnotationObserver(self)
    self.addLogObserver('stdio', self.script_observer)

  def interrupt(self, reason):
    self.script_observer.fixupLast(builder.EXCEPTION)
    return ProcessLogShellStep.interrupt(self, reason)

  def evaluateCommand(self, cmd):
    observer_result = self.script_observer.annotate_status
    # Check if ProcessLogShellStep detected a failure or warning also.
    log_processor_result = ProcessLogShellStep.evaluateCommand(self, cmd)
    return BuilderStatus.combine(observer_result, log_processor_result)

  def commandComplete(self, cmd):
    self.script_observer.handleReturnCode(cmd.rc)
    return ProcessLogShellStep.commandComplete(self, cmd)
