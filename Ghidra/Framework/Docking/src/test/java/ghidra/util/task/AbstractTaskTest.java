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
import java.util.concurrent.atomic.AtomicBoolean;

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
	protected volatile TaskDialogSpy dialogSpy;
	protected AtomicBoolean didRunInBackground = new AtomicBoolean();

	protected void assertDidNotRunInSwing() {
		for (TDEvent e : eventQueue) {
			assertFalse(e.getThreadName().contains("AWT"));
		}
	}

	protected void assertRanInSwingThread() {
		assertFalse("Task was not run in the Swing thread", didRunInBackground.get());
	}

	protected void assertSwingThreadBlockedForTask() {
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
		if (dialogSpy == null) {
			return; // not shown
		}

		assertFalse("Dialog should not have been shown.\nEvents: " + eventQueue,
			dialogSpy.wasShown());
	}

	protected void assertDialogShown() {
		assertTrue("Dialog should have been shown.\nEvents: " + eventQueue, dialogSpy.wasShown());
	}

	protected void waitForTask() throws Exception {
		threadsFinished.await(2, TimeUnit.SECONDS);
	}

	protected void launchTask(Task task) {
		launchTaskFromSwing(task);
	}

	protected void launchTaskFromSwing(Task task) {

		runSwing(() -> {
			taskLauncherSpy = new TaskLauncherSpy(task);
			postEvent("After task launcher");
			threadsFinished.countDown();
		});
	}

	protected void postEvent(String message) {
		eventQueue.add(new TDEvent(message));
	}

	protected class TaskLauncherSpy extends TaskLauncher {

		public TaskLauncherSpy(Task task) {
			super(task, null, DELAY_LAUNCHER);
		}

		@Override
		protected TaskRunner createTaskRunner(Task task, Component parent, int delay,
				int dialogWidth) {

			return new TaskRunner(task, parent, delay, dialogWidth) {
				@Override
				protected TaskDialog buildTaskDialog(Component comp, TaskMonitor monitor) {
					dialogSpy = new TaskDialogSpy(task) {
						@Override
						public synchronized boolean isCompleted() {
							return super.isCompleted() || isFinished();
						}
					};
					return dialogSpy;
				}
			};
		}

		@Override
		protected void runInThisBackgroundThread(Task task) {
			didRunInBackground.set(true);
			super.runInThisBackgroundThread(task);
		}

		TaskDialogSpy getDialogSpy() {
			return dialogSpy;
		}

		boolean didRunInBackground() {
			return didRunInBackground.get();
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
