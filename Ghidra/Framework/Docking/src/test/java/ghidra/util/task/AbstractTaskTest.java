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

import java.awt.Component;
import java.util.Deque;
import java.util.concurrent.*;

import docking.test.AbstractDockingTest;
import ghidra.util.Swing;

public class AbstractTaskTest extends AbstractDockingTest {

	protected static final int DELAY_FAST = 10;
	protected static final int DELAY_SLOW = TaskLauncher.INITIAL_MODAL_DELAY_MS + 100; // + some fudge
	protected static final int DELAY_NONMODAL_SLOW = TaskLauncher.INITIAL_DELAY_MS + 100; // + some fudge
	protected static final int DELAY_LAUNCHER = DELAY_FAST * 2;

	// 2 - 1 for the task itself; 1 for the launcher
	protected CountDownLatch threadsFinished = new CountDownLatch(2);
	protected Deque<TDEvent> eventQueue = new LinkedBlockingDeque<>();

	protected volatile TaskLauncherSpy taskLauncherSpy;
	protected volatile TaskDialog taskDialog;

	protected void assertDidNotRunInSwing() {
		for (TDEvent e : eventQueue) {
			assertFalse(e.getThreadName().contains("AWT"));
		}
	}

	protected void assertSwingThreadBlockedForTask() {
		// if the last event is the swing thread, then we know the task blocked that thread, since
		// the task delay would have made it run last had it not blocked
		waitForSwing();
		TDEvent lastEvent = eventQueue.peekLast();
		boolean swingIsLast = lastEvent.getThreadName().contains("AWT");
		if (!swingIsLast) {
			fail("The Swing thread did not block until the task finished.\nEvents: " + eventQueue);
		}
	}

	protected void assertSwingThreadFinishedBeforeTask() {
		waitForSwing();
		TDEvent lastEvent = eventQueue.peekLast();
		boolean swingIsLast = lastEvent.getThreadName().contains("AWT");
		if (swingIsLast) {
			fail("The Swing thread blocked until the task finished.\nEvents: " + eventQueue +
				"\nLast Event: " + lastEvent);
		}
	}

	protected void assertNoDialogShown() {
		if (taskDialog == null) {
			return; // not shown
		}

		assertFalse("Dialog should not have been shown.\nEvents: " + eventQueue,
			taskDialog.wasShown());
	}

	protected void assertDialogShown() {
		assertTrue("Dialog should have been shown.\nEvents: " + eventQueue, taskDialog.wasShown());
	}

	protected void waitForTask() throws Exception {
		threadsFinished.await(2, TimeUnit.SECONDS);
	}

	/**
	 * Launches the task and waits until the dialog is shown
	 * @param task the task to launch
	 */
	protected void launchTask(Task task) {
		launchTaskFromSwing(task);
	}

	protected void launchTaskWithoutBlocking(Task task) {
		runSwing(() -> launchTaskFromSwing(task), false);
		waitFor(() -> taskDialog != null);
	}

	protected void launchTaskFromSwing(Task task) {

		runSwing(() -> {
			taskLauncherSpy = new TaskLauncherSpy(task);
			postEvent("After task launcher");
			threadsFinished.countDown();
		});
	}

	protected void launchTaskFromSwing(FastModalTask task, int dialogDelay) {
		runSwing(() -> {
			taskLauncherSpy = new TaskLauncherSpy(task, dialogDelay);
			postEvent("After task launcher");
			threadsFinished.countDown();
		});
	}

	protected void postEvent(String message) {
		eventQueue.add(new TDEvent(message));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	protected class TaskLauncherSpy extends TaskLauncher {

		public TaskLauncherSpy(Task task) {
			this(task, DELAY_LAUNCHER);
		}

		public TaskLauncherSpy(Task task, int dialogDelay) {
			super(task, null, dialogDelay);
		}

		@Override
		protected TaskRunner createTaskRunner(Task task, Component parent, int delay,
				int dialogWidth) {

			return new TaskRunner(task, parent, delay, dialogWidth) {
				@Override
				protected TaskDialog buildTaskDialog() {
					taskDialog = super.buildTaskDialog();
					return taskDialog;
				}
			};
		}
	}

	protected class FastModalTask extends Task {

		public FastModalTask() {
			super("Fast Modal Task", true, true, true);
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(getName() + " started...");
			sleep(DELAY_FAST);
			threadsFinished.countDown();
			postEvent(getName() + " finished.");
		}
	}

	protected class FastNonModalTask extends Task {

		public FastNonModalTask() {
			super("Fast Non-modal Task", true, true, false);
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(getName() + " started...");
			sleep(DELAY_FAST);
			postEvent(getName() + " finished.");
			threadsFinished.countDown();
		}
	}

	protected class SlowModalTask extends Task {

		public SlowModalTask() {
			super("Slow Modal Task", true, true, true);
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(getName() + " started...");
			sleep(DELAY_SLOW);
			threadsFinished.countDown();
			postEvent(getName() + " finished.");
		}
	}

	protected class SlowNonModalTask extends Task {

		public SlowNonModalTask() {
			super("Slow Non-modal Task", true, true, false);
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(getName() + " started...");
			sleep(DELAY_NONMODAL_SLOW);
			Swing.runNow(() -> null);
			threadsFinished.countDown();
			postEvent(getName() + " finished.");
		}
	}

	protected class LatchedModalTask extends Task {

		private CountDownLatch latch;

		public LatchedModalTask(CountDownLatch latch) {
			super("Latched Modal Task", true, true, true);
			this.latch = latch;
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(getName() + " started...");
			waitFor(latch);
			sleep(DELAY_SLOW);
			threadsFinished.countDown();
			postEvent(getName() + " finished.");
		}
	}

	protected class TDEvent {

		protected String threadName = Thread.currentThread().getName();
		protected String message;

		TDEvent(String message) {
			this.message = message;

			// Msg.out(message + " from " + threadName);
		}

		String getThreadName() {
			return threadName;
		}

		@Override
		public String toString() {
			return message + " - thread [" + threadName + ']';
		}
	}
}
