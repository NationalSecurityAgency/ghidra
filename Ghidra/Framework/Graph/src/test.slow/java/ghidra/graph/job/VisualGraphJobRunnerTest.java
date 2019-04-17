/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.graph.job;

import static org.junit.Assert.*;

import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.*;

import generic.test.AbstractGTest;
import generic.test.AbstractGenericTest;
import ghidra.framework.LoggingInitialization;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;

public class VisualGraphJobRunnerTest extends AbstractGenericTest {

	// something reasonable: too large makes the test slower; too small, then the test can timeout
	private static final int RUN_TIME_MILLIS_JOB_THREAD_MAX = 1000;

	// keep this relatively low, since non-shortcut-able jobs run to completion	
	private static final int RUN_TIME_MILLIS_NON_SHORTCUTTABLE = 1000;

	private static final int RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED = DEFAULT_WAIT_TIMEOUT;

	private GraphJobRunner jobRunner = new GraphJobRunner();
	private Random random = new Random();
	private Logger logger;
	private WeakSet<JobExecutionThread> jobThreads =
		WeakDataStructureFactory.createCopyOnReadWeakSet();
	private int jobCount;

	@Before
	public void setUp() throws Exception {

		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");

		LoggingInitialization.initializeLoggingSystem();
		logger = LogManager.getLogger(GraphJobRunner.class);

		// enable tracing for debugging (note: this still requires the active log4j file 
		// to have the 'console' appender set to 'TRACE'
//		Configurator.setLevel(logger.getName(), org.apache.logging.log4j.Level.TRACE);
//
//		Logger myLogger = LogManager.getLogger(VisualGraphJobRunnerTest.class);
//		Configurator.setLevel(myLogger.getName(), org.apache.logging.log4j.Level.TRACE);
	}

	@After
	public void tearDown() {

		for (JobExecutionThread t : jobThreads) {
			t.killThread();
		}
	}

	@Test
	public void testRunJob() {
		BasicJob basicJob = new BasicJob();
		schedule(basicJob);
		waitForJobToStart(basicJob);
		waitForJobRunner();
		assertTrue(basicJob.isFinished());

		NonShortcuttableJob nonShortcuttableJob = new NonShortcuttableJob();
		schedule(nonShortcuttableJob);
		waitForJobToStart(nonShortcuttableJob);
		waitForJobRunner();
		assertTrue(nonShortcuttableJob.isFinished());
	}

	@Test
	public void testRunFinalJob() {
		BasicJob basicJob = new BasicJob();
		jobRunner.setFinalJob(basicJob);
		waitForJobRunner();
		assertTrue(basicJob.isFinished());
	}

	@Test
	public void testRunJobShortCutsRunningJob() {
		//
		// Test that running a new job will shortcut any currently running job that is 
		// shortcut-able
		//

		// put on a job that will run long enough for us to post a second job
		TimeBasedJob timeJob = new TimeBasedJob(RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED);
		schedule(timeJob);
		waitForJobToStart(timeJob);

		// post a second job
		BasicJob basicJob = new BasicJob();
		schedule(basicJob);

		waitForJobRunner();

		// make sure that the first job was shortcut and that our second job was run
		assertFinishedAndShortcut(timeJob);
		assertFinishedAndNotShortcut(basicJob);
	}

	@Test
	public void testRunJobDoesNotShortCutJobsThatCannotBeShortcut() {
		//
		// Test that running a new job will not shortcut any currently running job that is 
		// not shortcut-able
		//

		// put on a job that will run long enough for us to post a second job
		TimeBasedJob timeJob = new NonShortcuttableJob(RUN_TIME_MILLIS_NON_SHORTCUTTABLE);
		schedule(timeJob);
		waitForJobToStart(timeJob);

		// post a second job
		BasicJob basicJob = new BasicJob();
		schedule(basicJob);

		waitForJobRunner();

		// make sure that the first job was not shortcut and that our second job was run
		assertFinishedAndNotShortcut(timeJob, basicJob);
	}

	@Test
	public void testRunJobShortCutsQueuedJobsButLastOne() {
		// 
		// Test that we can add many jobs and that they all will be shortcut except for the last
		// one, which will be executed.
		//

		// start with a long running job to give us time to get jobs onto the queue
		TimeBasedJob timeJob = new TimeBasedJob(RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED);
		BasicJob basicJob1 = new BasicJob();
		BasicJob basicJob2 = new BasicJob();
		BasicJob basicJob3 = new BasicJob();
		BasicJob basicJob4 = new BasicJob();
		BasicJob lastJob = new BasicJob();

		schedule(timeJob);
		waitForJobToStart(timeJob);

		schedule(basicJob1);
		schedule(basicJob2);
		schedule(basicJob3);
		schedule(basicJob4);
		schedule(lastJob);

		waitForJobRunner();

		assertFinishedAndShortcut(timeJob);
		assertFinishedAndShortcut(basicJob1, basicJob2, basicJob3, basicJob4);
		assertFinishedAndNotShortcut(lastJob);
	}

	@Test
	public void testSchedule_ShortCutsQueuedJobs_ButNotThoseThatCannotBeShortcutOrThoseThatFollow() {
		// 
		// Test that we can add many jobs, with some in the middle that are not shortcut-able.
		// We expect those before that element to be shortcut.  Those after that element should
		// be run.
		//

		// start with a long running job to give us time to get jobs onto the queue
		TimeBasedJob timeJob = new TimeBasedJob(RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED);
		BasicJob basicJob1 = new BasicJob();
		BasicJob basicJob2 = new BasicJob();
		NonShortcuttableJob nsJob = new NonShortcuttableJob();
		BasicJob basicJob4 = new BasicJob();
		BasicJob lastJob = new BasicJob();

		schedule(timeJob);
		waitForJobToStart(timeJob);

		schedule(basicJob1);
		schedule(basicJob2);
		schedule(nsJob);
		schedule(basicJob4);
		schedule(lastJob);

		waitForJobRunner();

		assertFinishedAndShortcut(timeJob, basicJob1, basicJob2);
		assertFinishedAndNotShortcut(nsJob, basicJob4, lastJob);
	}

	@Test
	public void testSetFinalJobDoesNotShortCutRunningJob() {

		// start with a long running job to give us time to get jobs onto the queue
		NonShortcuttableJob nsJob = new NonShortcuttableJob(RUN_TIME_MILLIS_NON_SHORTCUTTABLE);
		BasicJob basicJob1 = new BasicJob();
		BasicJob finalJob = new BasicJob();

		schedule(nsJob);
		waitForJobToStart(nsJob);

		schedule(basicJob1);
		jobRunner.setFinalJob(finalJob);

		waitForJobRunner();

		assertTrue(basicJob1.isFinished());
		assertTrue(finalJob.isFinished());
	}

	@Test
	public void testFinalJobGetsRunAfterQueuedJobs() {
		// start with a long running job to give us time to get jobs onto the queue
		NonShortcuttableJob nsJob = new NonShortcuttableJob(RUN_TIME_MILLIS_NON_SHORTCUTTABLE);
		BasicJob basicJob1 = new BasicJob();
		BasicJob finalJob = new BasicJob();

		schedule(nsJob);
		schedule(basicJob1);
		jobRunner.setFinalJob(finalJob);

		waitForJobRunner();

		assertTrue(basicJob1.isFinished());
		assertTrue(finalJob.isFinished());

		assertTrue(basicJob1.getTimestamp() < finalJob.getTimestamp());
	}

	@Test
	public void testCannotScheduleFinishedJob() {

		FinishedJob job = new FinishedJob();
		AtomicReference<Throwable> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				jobRunner.schedule(job);
			}
			catch (IllegalArgumentException iae) {
				// good!
				ref.set(iae);
			}
		});

		assertNotNull("Did not get an exception attempting to schedule a finished job!", ref.get());
	}

	@Test
	public void testFinishAllJobs_WhenEmpty() {
		jobRunner.finishAllJobs();
		assertTrue(!jobRunner.isBusy());

		BasicJob job = new BasicJob();
		jobRunner.schedule(job);

		waitForJobRunner();

		assertTrue(job.isFinished());
		assertTrue("Job was not processed after clearing the job runner", !jobRunner.isBusy());
	}

	@Test
	public void testFinishAllJobs_WithFinalJob() {

		TimeBasedJob job = new TimeBasedJob(RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED);
		jobRunner.setFinalJob(job);
		waitForSwing();

		jobRunner.finishAllJobs();
		waitForSwing();

		assertTrue(job.isFinished());
		assertTrue("Job was not processed after clearing the job runner", !jobRunner.isBusy());
	}

	@Test
	public void testFinishAllJobs_WithCurrentJob_NoPendingJobs() {

		TimeBasedJob job = new TimeBasedJob(RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED);
		jobRunner.schedule(job);
		waitForJobToStart(job);

		jobRunner.finishAllJobs();
		waitForSwing();

		assertTrue(job.isFinished());
		assertTrue("Job was not processed after clearing the job runner", !jobRunner.isBusy());
	}

	@Test
	public void testFinishAllJobs_WithCurrentJob_WithPendingJobs() {

		ShortcuttableLatchJob latchJob = new ShortcuttableLatchJob();
		jobRunner.schedule(latchJob);
		waitForJobToStart(latchJob);

		BasicJob pending1 = new BasicJob();
		BasicJob pending2 = new BasicJob();
		jobRunner.schedule(pending1);
		jobRunner.schedule(pending2);

		// continue now that we have a current job and pending jobs in the runner
		latchJob.unblockQueue();

		jobRunner.finishAllJobs();
		waitForSwing();

		assertFinishedAndShortcut(latchJob, pending1, pending2);
		assertTrue("Job was not processed after clearing the job runner", !jobRunner.isBusy());
	}

	// No reliable way to get the runner into this state
	// public void testFinishAllJobs_NoCurrentJob_WithPendingJobs()

	@Test
	public void testDispose_WhenEmpty() {
		jobRunner.dispose();
		assertTrue(!jobRunner.isBusy());

		BasicJob job = new BasicJob();
		jobRunner.schedule(job);

		assertTrue("Job was processed after a dispose() call", !jobRunner.isBusy());
	}

	@Test
	public void testDispose_WithFinalJob() {

		TimeBasedJob job = new TimeBasedJob(RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED);
		jobRunner.setFinalJob(job);
		waitForSwing();

		jobRunner.dispose();
		waitForSwing();

		assertDisposedOrDidNotRun(job);
		assertTrue("Job was not processed after clearing the job runner", !jobRunner.isBusy());
	}

	@Test
	public void testDispose_WithCurrentJob_WithFinalJob() {

		TimeBasedJob job = new TimeBasedJob(RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED);
		jobRunner.schedule(job);
		waitForJobToStart(job);

		BasicJob finalJob = new BasicJob();
		jobRunner.setFinalJob(finalJob);

		jobRunner.dispose();
		waitForSwing();

		assertDisposedOrDidNotRun(job, finalJob);
		assertTrue("Job was not processed after clearing the job runner", !jobRunner.isBusy());
	}

	@Test
	public void testDispose_WithCurrentJob_NoPendingJobs() {

		TimeBasedJob job = new TimeBasedJob(RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED);
		jobRunner.schedule(job);
		waitForJobToStart(job);

		jobRunner.dispose();
		waitForSwing();

		assertDisposedOrDidNotRun(job);
		assertTrue("Job was not processed after clearing the job runner", !jobRunner.isBusy());
	}

	@Test
	public void testDispose_WithCurrentJob_WithPendingJobs() {

		NonShortcuttableLatchJob latchJob = new NonShortcuttableLatchJob();
		jobRunner.schedule(latchJob);
		waitForJobToStart(latchJob);

		BasicJob pending1 = new BasicJob();
		BasicJob pending2 = new BasicJob();
		jobRunner.schedule(pending1);
		jobRunner.schedule(pending2);

		//
		// At this point, the latch job is waiting for us to signal a finish.  We will not 
		// call finish, but instead, dispose the queue.
		//
		jobRunner.dispose();
		waitForSwing();

		assertDisposedOrDidNotRun(latchJob, pending1, pending2);
		assertTrue("Job was not processed after clearing the job runner", !jobRunner.isBusy());
	}

	// No reliable way to get the runner into this state
	//public void testDispose_NoCurrentJob_WithPendingJobs()

	@Test
	public void testFinishAllJobs_WithCurrentJob_FinalJobGetsRun() {

		TimeBasedJob job = new TimeBasedJob(RUN_TIME_MILLIS_FOR_JOB_TO_GET_STARTED);
		jobRunner.schedule(job);
		waitForSwing();

		BasicJob finalJob = new BasicJob();
		jobRunner.setFinalJob(finalJob);

		jobRunner.finishAllJobs();
		waitForSwing();

		assertFinishedAndShortcut(job, finalJob);
		assertTrue(!jobRunner.isBusy());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void schedule(GraphJob job) {
		jobRunner.schedule(job);
	}

	private void waitForJobToStart(AbstractTestGraphJob job) {
		waitForCondition(() -> job.didStart());
	}

	private void waitForJobRunner() {

		// the potential max thread runtime for a single job plus a single non-shortcut-able
		// job (most tests do not have more than one of each of these)
		int max = (RUN_TIME_MILLIS_JOB_THREAD_MAX + RUN_TIME_MILLIS_NON_SHORTCUTTABLE) * 2;
		waitForJobRunner(max);
	}

	private void waitForJobRunner(long maxTime) {

		logger.trace("\n\n@Test - done scheduling jobs; waiting for completion\n\n");

		long total = 0;
		while (jobRunner.isBusy() && total < maxTime) {
			total += sleep(DEFAULT_WAIT_DELAY);
			if (total >= maxTime) {
				throw new AssertException("Timed-out waiting for graph job runner to finish");
			}
		}

		logger.trace("\n\n\t@Test - done waiting\n\n");
	}

	private void assertFinishedAndShortcut(AbstractTestGraphJob... jobs) {

		StringBuilder buffy =
			new StringBuilder(jobs.length + " Jobs - both of these booleans must be true\n");
		for (AbstractTestGraphJob job : jobs) {
			boolean isFinished = job.isFinished();
			boolean didShortcut = job.didShortcut();

			buffy.append("\njob: ").append(job.toString()).append('\n');
			buffy.append("\tfinished? ").append(isFinished).append('\n');
			buffy.append("\tshortcut? ").append(didShortcut).append('\n');

			assertTrue("Job should have finished\n" + buffy, isFinished);
			assertTrue("Job should have been shortcut\n" + buffy, didShortcut);
		}
	}

	private void assertFinishedAndNotShortcut(AbstractTestGraphJob... jobs) {

		StringBuilder buffy =
			new StringBuilder(jobs.length + " Jobs - should be finsihed and not shortcut\n");
		for (AbstractTestGraphJob job : jobs) {

			boolean isFinished = job.isFinished();
			boolean didShortcut = job.didShortcut();

			buffy.append("\njob: ").append(job.toString()).append('\n');
			buffy.append("\tfinished? ").append(isFinished).append('\n');
			buffy.append("\tshortcut? ").append(didShortcut).append('\n');

			assertTrue("Job should have finished\n" + buffy, isFinished);
			assertFalse("Job should not have been shortcut\n" + buffy, didShortcut);
		}
	}

	private void assertDisposedOrDidNotRun(AbstractTestGraphJob... jobs) {

		StringBuilder buffy =
			new StringBuilder(jobs.length + " Jobs - one of these booleans must be true\n");
		for (AbstractTestGraphJob job : jobs) {
			boolean wasDisposed = job.isDisposed();
			boolean didNotStart = !job.didStart();

			buffy.append("\njob: ").append(job.toString()).append('\n');
			buffy.append("\tdisposed? ").append(wasDisposed).append('\n');
			buffy.append("\tnot started? ").append(didNotStart).append('\n');

			assertTrue("Job should have been diposed/cancelled\n" + buffy,
				wasDisposed || didNotStart);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class JobExecutionThread extends Thread {
		private final long runtime;
		private volatile boolean isFinished;
		private volatile boolean stopFlag;
		private volatile boolean killFlag;
		private final AbstractTestGraphJob job;

		JobExecutionThread(AbstractTestGraphJob job) {
			this(job, Math.max(500, random.nextInt(RUN_TIME_MILLIS_JOB_THREAD_MAX)));
		}

		JobExecutionThread(AbstractTestGraphJob job, long runtime) {
			super("Job Runner Thread - " + job);
			this.job = job;
			this.runtime = runtime;

			// track this thread for later cleanup
			jobThreads.add(this);
		}

		@Override
		public void run() {
			String methodName = "Thread.run()";
			logger.trace(methodName + " job starting (" + job + ")");

			if (stopFlag) {
				return; // stopped before we've started
			}

			long totalTime = 0;
			long sleepTime = 200;
			while (!stopFlag && totalTime < runtime) {
				logger.trace("\t" + methodName + " sleeping... (" + job + ") " + totalTime + " ms");
				totalTime += sleepTime;
				try {
					boolean keepSleeping = job.doSleep(sleepTime);
					if (!keepSleeping) {
						break;
					}
				}
				catch (InterruptedException e) {

					// just try again unless we have been explicitly told to stop
					if (stopFlag) {
						break;
					}
					Msg.error(this, "Interrupted while job thread was sleeping", e);
				}
			}

			if (killFlag) {
				return; // tear down
			}

			logger.trace("\t" + methodName + " preparing to call finished() (" + job + ")");
			job.threadFinished();
			logger.trace("\t" + methodName + " setting finished (" + job + ")");
			isFinished = true;
			jobThreads.remove(this);
		}

		void killThread() {
			killFlag = true;
			stopThread();
		}

		void stopThread() {

			if (isFinished) {
				return;
			}

			logger.trace(" stopThread() (" + job + ")");
			stopFlag = true;
			interrupt();

			long totalTime = 0;
			long sleepTime = 100;
			while (!isFinished && totalTime < 50) {
				logger.trace("\tstopThread() - waiting for thread (" + job + ")");
				totalTime += sleepTime;
				AbstractGTest.sleep(sleepTime);
			}
			logger.trace("\t\tstopThread() - done stopping thread (" + job + ")");
		}

		boolean isFinished() {
			logger.trace("Thread.isFinished()? " + isFinished + " (" + job + ")");
			return isFinished;
		}
	}

	private abstract class AbstractTestGraphJob implements GraphJob {
		protected volatile boolean didStart;
		protected volatile boolean didShortcut;
		protected volatile boolean didDispose;
		protected JobExecutionThread testThread;
		protected GraphJobListener jobListener;
		protected long timestampNanos;
		protected String name;

		AbstractTestGraphJob() {
			this.name = getClass().getSimpleName() + " (" + ++jobCount + ")";
		}

		// allows individual jobs to control how sleeping is done
		boolean doSleep(long sleepTime) throws InterruptedException {
			Thread.sleep(sleepTime);
			return true; // we always keep sleeping; subclasses may do something different
		}

		boolean isDisposed() {
			return didDispose;
		}

		@Override
		public void shortcut() {
			String methodName = "shortcut()";
			logger.trace(methodName + " (" + this + ")");
			didShortcut = true;

			if (testThread != null) {
				testThread.stopThread();
			}

			//
			// Note: this code is already on the Swing thread, as it is a callback from the runner
			//
			if (jobListener != null) {
				logger.trace(
					"\t" + methodName + " calling listener jobFinished()..." + " (" + this + ")");
				jobListener.jobFinished(this);
				logger.trace("\t\t" + methodName + " done calling listener (" + this + ")");
			}
			else {
				logger.trace("\t" + methodName +
					" job listener is null--shortcut() called before the job was started (" + this +
					")");
			}
		}

		void threadFinished() {

			String methodName = "threadFinished()";
			logger.trace(methodName + " (" + this + ")");
			if (didShortcut) {
				logger.trace("\t" + methodName + " was shortcut (" + this + ")");
				return; // the jobFinished() has been (or will be) called by the code of shortcut()
			}

			//
			// Note: this code is NOT on the Swing thread, as it is a callback from a Thread
			//
			logger.trace("\t" + methodName + " calling listiner on Swing thread... (" + this + ")");
			runSwing(() -> jobListener.jobFinished(AbstractTestGraphJob.this));

			logger.trace("\t" + methodName + " after listener call (" + this + ")");
		}

		@Override
		public boolean isFinished() {
			logger.trace(printDiagnostic());

			if (didShortcut) {
				logger.trace("\tJob.isFinished() - didShortcut; returning true (" + this + ")");
				return true;
			}

			boolean isFinished = testThread != null && testThread.isFinished();
			logger.trace("\tJob.isFinished() - was not shortcut; returning " + isFinished + " (" +
				this + ")");
			return isFinished;
		}

		String printDiagnostic() {

			String started = didStart ? "started" : "not started";
			String shortcut = didShortcut ? "was shortcut" : "not shortcut";
			String runState = "not running";
			if (testThread != null) {
				runState = testThread.isFinished() ? "finished" : "running";
			}

			String status = "Job.isFinished()?: " + started + " | " + shortcut + " | " + runState +
				" (" + toString() + ")";
			return status;
		}

		boolean didShortcut() {
			return didShortcut;
		}

		boolean didStart() {
			return didStart;
		}

		long getTimestamp() {
			return timestampNanos;
		}

		@Override
		public void execute(GraphJobListener listener) {
			didStart = true;
			this.jobListener = listener;
			testThread = new JobExecutionThread(this);
			testThread.start();
			timestampNanos = System.nanoTime();
		}

		@Override
		public void dispose() {
			didDispose = true;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	private class BasicJob extends AbstractTestGraphJob {

		@Override
		public boolean canShortcut() {
			return true;
		}
	}

	private class FinishedJob extends AbstractTestGraphJob {
		@Override
		public boolean isFinished() {
			return true;
		}

		@Override
		public boolean canShortcut() {
			return true;
		}
	}

	private class TimeBasedJob extends AbstractTestGraphJob {

		private final long runtime;

		TimeBasedJob() {
			runtime = 0; // random
		}

		TimeBasedJob(long runtime) {
			this.runtime = runtime;
		}

		@Override
		public void execute(GraphJobListener listener) {
			didStart = true;
			this.jobListener = listener;
			if (runtime == 0) {
				testThread = new JobExecutionThread(this);
			}
			else {
				testThread = new JobExecutionThread(this, runtime);
			}

			testThread.start();
			timestampNanos = System.nanoTime();
		}

		@Override
		public boolean canShortcut() {
			return true;
		}
	}

	private class NonShortcuttableJob extends TimeBasedJob {

		NonShortcuttableJob() {
			super();
		}

		NonShortcuttableJob(long runtime) {
			super(runtime);
		}

		@Override
		public boolean canShortcut() {
			return false;
		}

		@Override
		public void shortcut() {
			throw new AssertException("Called shortCut() on a job that cannot be shortcut");
		}
	}

	// A job that will block until told to proceed, which allows this test to manipulate how 
	// the job runner queue get managed; this job will actually block the job queue
	private class NonShortcuttableLatchJob extends AbstractTestGraphJob {

		private CountDownLatch pauseBackgroundThreadLatch = new CountDownLatch(1);

		@Override
		public boolean canShortcut() {
			return false;
		}

		@Override
		public void shortcut() {
			// should not be called, since we cannot be shortcut
			throw new IllegalStateException("Not expecting shortcut to be called");
		}

		@Override
		boolean doSleep(long sleepTime) throws InterruptedException {

			// we will only 'sleep' as long as our latch is pending
			try {
				pauseBackgroundThreadLatch.await(sleepTime, TimeUnit.MILLISECONDS);
			}
			catch (InterruptedException e) {
				throw e;
			}

			// keep sleeping until the latch is triggered
			return pauseBackgroundThreadLatch.getCount() != 0;
		}

		@Override
		public void dispose() {
			didDispose = true;
			releaseJob();
		}

		void releaseJob() {
			pauseBackgroundThreadLatch.countDown();
		}
	}

	// A job that will block until told to proceed, which allows this test to manipulate how 
	// the job runner queue get managed; this job will actually block the job queue
	private class ShortcuttableLatchJob extends AbstractTestGraphJob {

		private CountDownLatch pauseQueueLatch = new CountDownLatch(1);

		@Override
		public boolean canShortcut() {
			// this class needs to be shortcut-able so that the job runner being tested 
			// will attempt to shortcut it
			return true;
		}

		@Override
		public void execute(GraphJobListener listener) {
			super.execute(listener);
			try {
				// this is called directly by the queue, so blocking here stops the queue, which
				// is in the Swing thread
				pauseQueueLatch.await(10, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				Msg.error(this, "Exception waiting for latch", e);
			}
		}

		@Override
		public void shortcut() {
			if (pauseQueueLatch.getCount() == 1) {
				// should't happen, since we are blocking the job queue
				throw new IllegalStateException("Not expecting shortcut to be called with a latch");
			}
			super.shortcut();
		}

		@Override
		public void dispose() {
			didDispose = true;
			Msg.debug(this, "dispose()...");
			pauseQueueLatch.countDown();
			Msg.debug(this, "\treleased latch");
			testThread.stopThread();
			Msg.debug(this, "\tstopped thread");
		}

		void unblockQueue() {
			pauseQueueLatch.countDown();
		}
	}
}
