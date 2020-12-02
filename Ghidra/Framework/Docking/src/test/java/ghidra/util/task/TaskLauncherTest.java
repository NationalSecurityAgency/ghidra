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

import static org.junit.Assert.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.*;

public class TaskLauncherTest extends AbstractTaskTest {

	private Thread swingThread;

	@Before
	public void setUp() {
		runSwing(() -> swingThread = Thread.currentThread());
	}

	@After
	public void tearDown() {
		// release any blockers
		swingThread.interrupt();
	}

	@Test
	public void testLaunchFromSwing() throws Exception {

		FastModalTask task = new FastModalTask();
		launchTaskFromSwing(task);
		waitForTask();
		assertSwingThreadBlockedForTask();
	}

	@Test
	public void testLaunchFromBackground() throws Exception {

		FastModalTask task = new FastModalTask();
		launchTaskFromBackground(task);
		waitForTask();
		assertDidNotRunInSwing();
	}

	@Test
	public void testLaunchFromBackgroundWithBusySwing() throws Exception {

		SwingBlocker blocker = new SwingBlocker();
		runSwing(blocker, false);
		blocker.waitForStart();

		FastModalTask task = new FastModalTask();
		launchTaskFromBackground(task);
		waitForTask();

		assertDidNotRunInSwing();
	}

	@Test
	public void testLaunchFromInsideOfAnotherTaskThread() throws Exception {

		SwingBlocker blocker = new SwingBlocker();
		runSwing(blocker, false);
		blocker.waitForStart();

		// 4 - 2 per task
		threadsFinished = new CountDownLatch(4);
		launchTaskFromTask();
		waitForTask();
		assertDidNotRunInSwing();
	}

	@Test
	public void testLaunchFromInsideOfAnotherTaskThreadWithBusySwingThread() throws Exception {

		// 4 - 2 per task
		threadsFinished = new CountDownLatch(4);
		launchTaskFromTask();
		waitForTask();
		assertDidNotRunInSwing();
	}

	@Test
	public void testLaunchFromSwingThreadWithModalTaskDoesNotBlockForFullDelay() throws Exception {

		//
		// Tests that a short-lived task does not block for the full dialog delay
		//

		FastModalTask task = new FastModalTask();
		int dialogDelay = 3000;
		long start = System.nanoTime();
		launchTaskFromSwing(task, dialogDelay);
		waitForTask();
		long end = System.nanoTime();
		long totalTime = TimeUnit.NANOSECONDS.toMillis(end - start);

		assertSwingThreadBlockedForTask();
		assertTrue(
			"Time waited is longer that the dialog delay: " + totalTime + " vs " + dialogDelay,
			totalTime < dialogDelay);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private int getWaitTimeoutInSeconds() {
		return (int) TimeUnit.SECONDS.convert(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS) * 2;
	}

	private void launchTaskFromBackground(Task task) throws InterruptedException {

		CountDownLatch start = new CountDownLatch(1);
		new Thread("Test Task Launcher Background Client") {
			@Override
			public void run() {
				taskLauncherSpy = new TaskLauncherSpy(task);
				start.countDown();
				postEvent("After task launcher");
				threadsFinished.countDown();
			}
		}.start();

		assertTrue("Background thread did not start in " + getWaitTimeoutInSeconds() + " seconds",
			start.await(getWaitTimeoutInSeconds(), TimeUnit.SECONDS));
	}

	private void launchTaskFromTask() throws InterruptedException {

		TaskLaunchingTask task = new TaskLaunchingTask();

		CountDownLatch start = new CountDownLatch(1);
		new Thread("Nested Test Task Launcher Background Client") {
			@Override
			public void run() {
				taskLauncherSpy = new TaskLauncherSpy(task);
				start.countDown();
				postEvent("After task launcher");
				threadsFinished.countDown();
			}
		}.start();

		assertTrue("Background thread did not start in " + getWaitTimeoutInSeconds() + " seconds",
			start.await(getWaitTimeoutInSeconds(), TimeUnit.SECONDS));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TaskLaunchingTask extends Task {

		public TaskLaunchingTask() {
			super("Slow Modal Task", true, true, true);
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(getName() + " started...");

			sleep(DELAY_FAST);
			try {
				launchTaskFromBackground(new FastModalTask());
			}
			catch (InterruptedException e) {
				throw new RuntimeException(e);
			}

			threadsFinished.countDown();
			postEvent(getName() + " finished.");
		}
	}

	private class SwingBlocker implements Runnable {

		private static final long REALLY_LONG_SLEEP_THAT_DOESNT_FINISH_MS = 20000;

		private CountDownLatch started = new CountDownLatch(1);

		@Override
		public void run() {
			started.countDown();
			sleep(REALLY_LONG_SLEEP_THAT_DOESNT_FINISH_MS);
		}

		void waitForStart() throws InterruptedException {
			assertTrue("Swing blocker did not start",
				started.await(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS));
		}

	}
}
