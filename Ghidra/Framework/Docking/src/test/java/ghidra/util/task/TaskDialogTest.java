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
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.StringUtils;
import org.junit.After;
import org.junit.Test;

import docking.test.AbstractDockingTest;

public class TaskDialogTest extends AbstractDockingTest {

	private static final int DELAY_FAST = 10;
	private static final int DELAY_SLOW = 100;
	private static final int DELAY_LAUNCHER = DELAY_FAST * 2;

	private CountDownLatch threadsFinished = new CountDownLatch(2);

	private Deque<TDEvent> eventQueue = new LinkedBlockingDeque<>();

	@After
	public void tearDown() {
		waitForSwing();
	}

	@Test
	public void testModalDialog_FastTask_NoDialog() throws Exception {

		FastModalTask task = new FastModalTask();

		TaskDialogSpy dialogSpy = launchTask(task);

		waitForTask();

		assertFalse(dialogSpy.wasShown());
		assertSwingThreadBlockedForTask();
	}

	@Test
	public void testModalDialog_SlowTask_Dialog() throws Exception {
		SlowModalTask task = new SlowModalTask();

		TaskDialogSpy dialogSpy = launchTask(task);

		waitForTask();

		assertTrue(dialogSpy.wasShown());
		assertSwingThreadBlockedForTask();
	}

	@Test
	public void testNonModalDialog_FastTask_NoDialog() throws Exception {

		FastNonModalTask task = new FastNonModalTask();

		TaskDialogSpy dialogSpy = launchTask(task);

		waitForTask();

		assertFalse(dialogSpy.wasShown());
		assertSwingThreadFinishedBeforeTask();
	}

	@Test
	public void testNonModalDialog_SlowTask_Dialog() throws Exception {

		SlowNonModalTask task = new SlowNonModalTask();

		TaskDialogSpy dialogSpy = launchTask(task);

		waitForTask();

		assertTrue(dialogSpy.wasShown());
		assertSwingThreadFinishedBeforeTask();
	}

	private void assertSwingThreadBlockedForTask() {
		TDEvent lastEvent = eventQueue.peekLast();
		boolean swingIsLast = lastEvent.getThreadName().contains("AWT");
		if (!swingIsLast) {
			System.out.println("Events " + eventQueue);
			fail("The Swing thread did not block until the task finished");
		}
	}

	private void assertSwingThreadFinishedBeforeTask() {
		int size = eventQueue.size();
		TDEvent lastEvent = eventQueue.peekLast();
		boolean swingIsLast = lastEvent.getThreadName().contains("AWT");
		if (swingIsLast) {
			System.out.println("Events (" + size + ")\n\t" + StringUtils.join(eventQueue, "\n\t"));
			fail("The Swing thread blocked until the task finished");
		}
	}

	private void waitForTask() throws Exception {
		threadsFinished.await(2, TimeUnit.SECONDS);
	}

	private TaskDialogSpy launchTask(Task task) {
		AtomicReference<TaskDialogSpy> ref = new AtomicReference<>();
		runSwing(() -> {
			TaskLauncherSpy launcherSpy = new TaskLauncherSpy(task);
			postEvent("After task launcher");
			TaskDialogSpy dialogSpy = launcherSpy.getDialogSpy();
			ref.set(dialogSpy);
			threadsFinished.countDown();
		});
		return ref.get();
	}

	private void postEvent(String message) {
		eventQueue.add(new TDEvent(message));
	}

	private class TaskLauncherSpy extends TaskLauncher {

		private TaskDialogSpy dialogSpy;

		public TaskLauncherSpy(Task task) {
			super(task, null, DELAY_LAUNCHER);
		}

		@Override
		protected TaskDialog createTaskDialog(Component comp) {
			dialogSpy = new TaskDialogSpy(task);
			return dialogSpy;
		}

		TaskDialogSpy getDialogSpy() {
			return dialogSpy;
		}
	}

	private class TaskDialogSpy extends TaskDialog {

		private AtomicBoolean shown = new AtomicBoolean();

		public TaskDialogSpy(Task task) {
			super(task);
		}

		@Override
		protected void doShow() {
			shown.set(true);
			super.doShow();
		}

		boolean wasShown() {
			return shown.get();
		}
	}

	private class FastModalTask extends Task {

		public FastModalTask() {
			super("Fast Modal Task", true, true, true);
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(" started...");
			sleep(DELAY_FAST);
			threadsFinished.countDown();
			postEvent(" finished.");
		}
	}

	private class FastNonModalTask extends Task {

		public FastNonModalTask() {
			super("Fast Non-modal Task", true, true, false);
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(" started...");
			sleep(DELAY_FAST);
			postEvent(" finished.");
			threadsFinished.countDown();
		}
	}

	private class SlowModalTask extends Task {

		public SlowModalTask() {
			super("Slow Modal Task", true, true, true);
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(" started...");
			sleep(DELAY_SLOW);
			threadsFinished.countDown();
			postEvent(" finished.");
		}
	}

	private class SlowNonModalTask extends Task {

		public SlowNonModalTask() {
			super("Slow Non-modal Task", true, true, false);
		}

		@Override
		public void run(TaskMonitor monitor) {
			postEvent(" started...");
			sleep(DELAY_SLOW);
			threadsFinished.countDown();
			postEvent(" finished.");
		}
	}

	private class TDEvent {

		private String threadName = Thread.currentThread().getName();
		private String message;

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
