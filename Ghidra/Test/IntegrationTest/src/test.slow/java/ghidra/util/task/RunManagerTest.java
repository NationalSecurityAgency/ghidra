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
package ghidra.util.task;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.awt.Container;
import java.util.Random;
import java.util.concurrent.*;

import javax.swing.JComponent;
import javax.swing.JFrame;

import org.junit.Assert;
import org.junit.Test;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;

public class RunManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private static final int THREADED_TEST_COUNT = 4;
	public static final int MAX_RUNNABLES_FROM_THREAD = 15;
	public static final int MAX_THREAD_DELAY_MILLIS = 150;
	public static final int MAX_WAIT_TIME =
		(MAX_RUNNABLES_FROM_THREAD * MAX_THREAD_DELAY_MILLIS) * THREADED_TEST_COUNT + 500;

	private volatile boolean failed = false;

	private volatile TestRunnable lastCreatedMultiThreadedTestRunner;

	public RunManagerTest() {
		super();
	}

	@Override
	protected void testFailed(Throwable e) {
		failed = true;
	}

	@Test
	public void testRunNow() {
		TestTaskListener listener = new TestTaskListener();
		RunManager runManager = new RunManager(listener);
		BasicTestRunnable runnable = new BasicTestRunnable();

		runManager.runNow(runnable, "Test Runnable", 500);

		waitForRunManagerToFinish(runManager);

		waitForPostedSwingRunnables();

		assertEquals(0, listener.taskCancelled);
		assertEquals(1, listener.taskCompleted);
	}

	@Test
	public void testRunNext() {
		//
		// Test that posting a runnable when one is currently running will not cancel the
		// currently running runnable, but will clear the queue of any other pending 
		// runnables
		//

		TestTaskListener listener = new TestTaskListener();
		RunManager runManager = new RunManager(listener);
		TimeSpecificTestRunnable firstRunnable = new TimeSpecificTestRunnable(3000);

		// this first call to runNext() should start the runnable instantly
		trace(testName.getMethodName() + "starting first runnable");
		runManager.runNext(firstRunnable, "Test Runnable", 500);

		waitForRunManagerToStart(runManager, firstRunnable);

		// this call to runNext() should allow the first runnable to finish
		trace(testName.getMethodName() + "starting second runnable");
		BasicTestRunnable secondRunnable = new BasicTestRunnable();
		runManager.runNext(secondRunnable, "Test Runnable", 500);

		trace(testName.getMethodName() + "waiting for run manager");
		waitForRunManagerToFinish(runManager);

		waitForPostedSwingRunnables();

		assertEquals(2, listener.taskCompleted);
		assertEquals(0, listener.taskCancelled);// no cancel (only internal cancel)

		assertTrue(firstRunnable.hasCompleted());
		assertTrue(secondRunnable.hasCompleted());
	}

	@Test
	public void testCancel_SingleRunnable() {
		TestTaskListener listener = new TestTaskListener();
		RunManager runManager = new RunManager(listener);

		TimeSpecificTestRunnable runnable = new TimeSpecificTestRunnable(10000);

		runManager.runNow(runnable, "Test Runnable", 500);

		waitForRunManagerToStart(runManager, runnable);

		runManager.cancelAllRunnables();

		waitForRunnableToFinish(runManager, runnable);

		assertTrue(!runnable.hasCompleted());
	}

	@Test
	public void testCancel_MultipleRunnables() {
		TestTaskListener listener = new TestTaskListener();
		RunManager runManager = new RunManager(listener);

		TimeSpecificTestRunnable runnable = new TimeSpecificTestRunnable(10000);

		runManager.runLater(runnable, "Test Runnable", 500);

		waitForRunManagerToStart(runManager, runnable);

		BasicTestRunnable secondRunnable = new BasicTestRunnable();
		BasicTestRunnable thirdRunnable = new BasicTestRunnable();
		BasicTestRunnable fourthRunnable = new BasicTestRunnable();

		runManager.runLater(secondRunnable, "Test Runnable", 500);
		runManager.runLater(thirdRunnable, "Test Runnable", 500);
		runManager.runLater(fourthRunnable, "Test Runnable", 500);

		runManager.cancelAllRunnables();

		waitForRunManagerToFinish(runManager);

		assertTrue(!secondRunnable.hasCompleted());
		assertTrue(!thirdRunnable.hasCompleted());
		assertTrue(!fourthRunnable.hasCompleted());
	}

	@Test
	public void testRunLater() {
		TestTaskListener listener = new TestTaskListener();
		RunManager runManager = new RunManager(listener);

		BasicTestRunnable runnable = new BasicTestRunnable();

		runManager.runLater(runnable, "Test Runnable", 500);

		waitForRunManagerToFinish(runManager);

		assertTrue(runnable.hasCompleted());
	}

	@Test
	public void testSchedule_CancelOnlyStopsCurrentRunnable() {
		TestTaskListener listener = new TestTaskListener();
		RunManager runManager = new RunManager(listener);

		TimeSpecificTestRunnable runnable = new TimeSpecificTestRunnable(10000);

		runManager.runLater(runnable, "Test Runnable", 500);

		waitForRunManagerToStart(runManager, runnable);

		BasicTestRunnable secondRunnable = new BasicTestRunnable();
		BasicTestRunnable thirdRunnable = new BasicTestRunnable();
		BasicTestRunnable fourthRunnable = new BasicTestRunnable();

		runManager.runLater(secondRunnable, "Test Runnable", 500);
		runManager.runLater(thirdRunnable, "Test Runnable", 500);
		runManager.runLater(fourthRunnable, "Test Runnable", 500);

		trace("Cancelling monitor!");
		TaskMonitor monitor = (TaskMonitor) getInstanceField("monitor", runManager);
		monitor.cancel();

		waitForRunnableToFinish(runManager, fourthRunnable);

		assertTrue(secondRunnable.hasCompleted());
		assertTrue(thirdRunnable.hasCompleted());
		assertTrue(fourthRunnable.hasCompleted());
	}

	@Test
	public void testManyRunCallsFromMultipleThreads() {
		RunManager runManager = new RunManager();

		CyclicBarrier startBarrier = new CyclicBarrier(THREADED_TEST_COUNT);
		CountDownLatch finishedLatch = new CountDownLatch(THREADED_TEST_COUNT);

		for (int i = 0; i < THREADED_TEST_COUNT; i++) {
			new RunnerThread("Thread " + (i + 1), runManager, startBarrier, finishedLatch).start();
		}

		try {
			finishedLatch.await();
		}
		catch (InterruptedException e) {
			Assert.fail("Unable to wait for worker threads to finish!");
		}

		// make sure the last runnable in actually completed
		waitForRunnableToFinish(runManager, lastCreatedMultiThreadedTestRunner);
		assertTrue(lastCreatedMultiThreadedTestRunner.hasCompleted());
	}

	@Test
	public void testSwingRunnerCallback() {
		TestTaskListener listener = new TestTaskListener();
		RunManager runManager = new RunManager(listener);
		TestSwingRunnable runnable = new TestSwingRunnable();

		runManager.runNow(runnable, "Test Swing Runnable");

		waitForRunManagerToFinish(runManager);

		waitForPostedSwingRunnables();

		assertTrue(runnable.hasCompleted());
		assertTrue(runnable.swingRunRan());
	}

	@Test
	public void testTaskListenerTaskCompleted() {
		TestTaskListener listener = new TestTaskListener();
		RunManager runManager = new RunManager(listener);
		BasicTestRunnable runnable = new BasicTestRunnable();

		runManager.runNow(runnable, "Test Runnable");

		waitForRunManagerToFinish(runManager);

		waitForPostedSwingRunnables();

		assertEquals(0, listener.taskCancelled);
		assertEquals(1, listener.taskCompleted);
	}

	@Test
	public void testTaskListenerTaskCancelled() {
		TestTaskListener listener = new TestTaskListener();
		RunManager runManager = new RunManager(listener);
		RunUntilCancelledTestRunnable runnable = new RunUntilCancelledTestRunnable();

		runManager.runNow(runnable, "Test Runnable");

		waitForRunManagerToStart(runManager, runnable);

		runManager.cancelAllRunnables();

		waitForRunnableToFinish(runManager, runnable);

		Msg.debug(this, "before waiting");
		waitForPostedSwingRunnables();
		Msg.debug(this, "after waiting");

		assertEquals(0, listener.taskCompleted);
		assertEquals(1, listener.taskCancelled);
	}

	@Test
	public void testProgressBarShowsAfterDelay_NoCancel() {
		//
		// Test that the progress bar will be shown after the defined delay and will be hidden
		// when completed.
		//
		RunManager runManager = new RunManager();

		JFrame frame = new JFrame("Progress Panel Test Frame");
		Container contentPane = frame.getContentPane();
		contentPane.add(runManager.getMonitorComponent());
		frame.setSize(200, 200);
		frame.setVisible(true);

		JComponent component = runManager.getMonitorComponent();
		CountDownLatch startLatch = new CountDownLatch(1);
		LatchRunnable runnable = new LatchRunnable(startLatch);
		assertTrue(!component.isShowing());

		// long enough that our two threads will have time to start and sleep without the 
		// thread schedule causing spurious failures
		int delay = 2500;
		runManager.runNow(runnable, "Test of Progress Bar Runnable", delay);

		waitForRunManagerToStart(runManager, runnable);

		try {
			Thread.sleep(delay / 3);
		}
		catch (InterruptedException e) {
			Assert.fail("Interrupted while sleeping for test");
		}

		assertTrue(!component.isShowing());

		try {
			Thread.sleep(delay);
		}
		catch (InterruptedException e) {
			Assert.fail("Interrupted while sleeping for test");
		}

		waitForPostedSwingRunnables();
		assertTrue(component.isShowing());

		startLatch.countDown();

		waitForRunManagerToFinish(runManager);

		waitForPostedSwingRunnables();
		waitForComponentToBeHidden(component);
		frame.setVisible(false);
	}

	private void waitForComponentToBeHidden(JComponent component) {
		int numWaits = 0;
		int sleepyTime = 100;
		int maxWaits = 20;

		while (component.isShowing() && maxWaits > numWaits++) {
			sleep(sleepyTime);
		}

		if (numWaits >= maxWaits) {
			Assert.fail("Component not hidden!");
		}
	}

	@Test
	public void testProgressBarShowsAfterDelay_WithCancel() {
		//
		// Test that the progress bar will be shown after the defined delay and will be hidden
		// when cancelled.
		//
		RunManager runManager = new RunManager();

		JFrame frame = new JFrame("Progress Panel Test Frame");
		Container contentPane = frame.getContentPane();
		contentPane.add(runManager.getMonitorComponent());
		frame.setSize(200, 200);
		frame.setVisible(true);

		RunUntilCancelledTestRunnable runnable = new RunUntilCancelledTestRunnable();

		JComponent component = runManager.getMonitorComponent();
		assertTrue(!component.isShowing());

		// long enough that our two threads will have time to start and sleep without the 
		// thread schedule causing spurious failures
		int delay = 5000;
		runManager.runNow(runnable, "Test of Progress Bar Runnable", delay);

		waitForRunManagerToStart(runManager, runnable);

		try {
			Thread.sleep(delay / 3);
		}
		catch (InterruptedException e) {
			Assert.fail("Interrupted while sleeping for test");
		}

		assertTrue(!component.isShowing());

		try {
			Thread.sleep(delay);
		}
		catch (InterruptedException e) {
			Assert.fail("Interrupted while sleeping for test");
		}

		waitForPostedSwingRunnables();
		assertTrue(component.isShowing());

		runManager.cancelAllRunnables();
		runManager.waitForNotBusy(DEFAULT_WINDOW_TIMEOUT);

		waitForPostedSwingRunnables();
		assertTrue(!component.isShowing());
		frame.setVisible(false);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void waitForRunManagerToStart(RunManager runManager, TestRunnable runnable) {
		assertTrue("Failed waiting for runnable to start", runnable.waitForStart(MAX_WAIT_TIME));
	}

	private void waitForRunnableToFinish(RunManager runManager, TestRunnable runnable) {

		waitForRunManagerToStart(runManager, runnable);

		assertTrue("Timed out waiting for runnable to finish",
			runnable.waitForFinished(MAX_WAIT_TIME));
	}

	private void waitForRunManagerToFinish(RunManager runManager) {
		runManager.waitForNotBusy(MAX_WAIT_TIME);
	}

	private void trace(String message) {
		System.err.println(message);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class RunnerThread extends Thread {

		private final RunManager runManager;
		private final Random random = new Random();

		private final CountDownLatch finishedLatch;
		private final CyclicBarrier startBarrier;

		RunnerThread(String name, RunManager runManager, CyclicBarrier startBarrier,
				CountDownLatch finishedLatch) {
			super(name);
			this.runManager = runManager;
			this.startBarrier = startBarrier;
			this.finishedLatch = finishedLatch;
		}

		@Override
		public void run() {
			try {
				// wait for all threads to start
				startBarrier.await();
			}
			catch (Exception e1) {
				System.err.println("Interrupted while waiting to begin: " + getName());
				e1.printStackTrace();
			}

			int runnableCount = random.nextInt(MAX_RUNNABLES_FROM_THREAD);
			trace(getName() + " - running runnables: " + runnableCount);
			for (int i = 0; i < runnableCount; i++) {

				int sleepyTime = random.nextInt(MAX_THREAD_DELAY_MILLIS);
				try {
					Thread.sleep(sleepyTime);
				}
				catch (InterruptedException e) {
					// don't care; we tried
				}

				synchronized (RunManagerTest.this) {
					lastCreatedMultiThreadedTestRunner =
						new NotExpectedToBeInterruptedTestRunnable();
					runManager.runNow(lastCreatedMultiThreadedTestRunner,
						"Thread Runnable " + i + " (" + getName() + ")");
				}
			}

			finishedLatch.countDown();
		}
	}

	private class TestTaskListener implements TaskListener {
		private volatile int taskCancelled;
		private volatile int taskCompleted;

		@Override
		public void taskCancelled(Task task) {
			trace("taskCancelled() - " + task);
			taskCancelled++;
		}

		@Override
		public void taskCompleted(Task task) {
			trace("taskCompleted()");
			taskCompleted++;
		}
	}

	private abstract class TestRunnable implements MonitoredRunnable {
		protected volatile boolean completedNormally;
		protected CountDownLatch startLatch = new CountDownLatch(1);
		protected CountDownLatch doneLatch = new CountDownLatch(1);

		boolean waitForStart(int timeout) {
			try {
				return startLatch.await(timeout, TimeUnit.MILLISECONDS);
			}
			catch (InterruptedException e) {
				trace("Interrupted waiting for start on latch");
				return false;
			}
		}

		boolean waitForFinished(int timeout) {
			try {
				return doneLatch.await(timeout, TimeUnit.MILLISECONDS);
			}
			catch (InterruptedException e) {
				trace("Interrupted waiting for finish on latch");
				return false;
			}
		}

		boolean hasCompleted() {
			return completedNormally;
		}
	}

	private class LatchRunnable extends TestRunnable {

		private final CountDownLatch delayLatch;

		LatchRunnable(CountDownLatch delayLatch) {
			this.delayLatch = delayLatch;
		}

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			trace(getClass().getSimpleName() + " - started");
			startLatch.countDown();

			try {
				delayLatch.await();
			}
			catch (Exception e) {
				System.err.println(
					"Interrupted while waiting to begin: " + testName.getMethodName());
				e.printStackTrace();
			}

			try {
				trace("\t" + getClass().getSimpleName() + " - sleeping");
				Thread.sleep(250);
				completedNormally = true;
			}
			catch (InterruptedException e) {
				// don't care; we are fake
			}

			trace("\t" + getClass().getSimpleName() + " - finished");
			doneLatch.countDown();
		}

	}

	private class TestSwingRunnable extends TestRunnable implements SwingRunnable {

		private volatile boolean swingRunRan;

		@Override
		public void swingRun(boolean isCancelled) {
			swingRunRan = true;
		}

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			trace(getClass().getSimpleName() + " - started");
			startLatch.countDown();
			try {
				trace("\t" + getClass().getSimpleName() + " - sleeping");
				Thread.sleep(250);
				completedNormally = true;
			}
			catch (InterruptedException e) {
				// don't care; we are fake
			}
			trace("\t" + getClass().getSimpleName() + " - finished");
			doneLatch.countDown();
		}

		boolean swingRunRan() {
			return swingRunRan;
		}
	}

	private class TimeSpecificTestRunnable extends TestRunnable {
		private final long timeInMillis;

		TimeSpecificTestRunnable(long timeInMillis) {
			this.timeInMillis = timeInMillis;
		}

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			trace(getClass().getSimpleName() + " - started");

			startLatch.countDown();

			int totalTime = 0;
			while (totalTime < timeInMillis && !monitor.isCancelled()) {
				try {
					trace("\t" + getClass().getSimpleName() + " - sleeping");
					Thread.sleep(250);
				}
				catch (InterruptedException e) {
					// don't care; we are fake
				}
				totalTime += 250;
			}

			if (monitor.isCancelled()) {
				trace("\t" + getClass().getSimpleName() + " - cancelled");
				doneLatch.countDown();
				return;
			}

			completedNormally = true;
			trace("\t" + getClass().getSimpleName() + " - finished");
			doneLatch.countDown();
		}
	}

	private class BasicTestRunnable extends TestRunnable {

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			trace(getClass().getSimpleName() + " - started");
			startLatch.countDown();

			if (monitor.isCancelled()) {
				trace("\t" + getClass().getSimpleName() + " - cancelled");
				doneLatch.countDown();
				return;
			}

			try {
				trace("\t" + getClass().getSimpleName() + " - sleeping");
				Thread.sleep(250);
				completedNormally = true;
			}
			catch (InterruptedException e) {
				// don't care; we are fake
			}
			trace("\t" + getClass().getSimpleName() + " - finished");
			doneLatch.countDown();
		}
	}

	private class NotExpectedToBeInterruptedTestRunnable extends TestRunnable {

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			trace(getClass().getSimpleName() + " - started");
			startLatch.countDown();

			int numWaits = 0;
			int sleepyTime = 500;
			int maxWaits = 10;

			while (!failed && !monitor.isCancelled() && maxWaits > numWaits++) {
				try {
					trace("\t" + getClass().getSimpleName() + " - sleeping");
					Thread.sleep(sleepyTime);
				}
				catch (InterruptedException e) {
					trace("\t" + getClass().getSimpleName() + " - interrupted - " +
						monitor.isCancelled());
					doneLatch.countDown();
					return;
				}
			}

			if (!monitor.isCancelled()) {
				completedNormally = true;
				trace("\t" + getClass().getSimpleName() + " - completed normally");
			}
			else {
				trace("\t" + getClass().getSimpleName() + " - completed - cancelled");
			}
			doneLatch.countDown();
		}
	}

	private class RunUntilCancelledTestRunnable extends TestRunnable {

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			trace(getClass().getSimpleName() + " - started");
			startLatch.countDown();

			while (!failed && !monitor.isCancelled()) {
				try {
					trace("\t" + getClass().getSimpleName() + " - sleeping");
					Thread.sleep(250);
				}
				catch (InterruptedException e) {
					// don't care; we will check the monitor above to know if we 
					// were cancelled
					trace("\t" + getClass().getSimpleName() + " - interrupted - " +
						monitor.isCancelled());
				}
			}

			if (!monitor.isCancelled()) {
				completedNormally = true;
				trace("\t" + getClass().getSimpleName() + " - completed normally");
			}
			else {
				trace("\t" + getClass().getSimpleName() + " - completed - cancelled");
			}
			doneLatch.countDown();
		}

	}
}
