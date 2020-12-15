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

import org.junit.After;
import org.junit.Test;

public class TaskDialogTest extends AbstractTaskTest {

	@After
	public void tearDown() {
		waitForSwing();
	}

	@Test
	public void testModalDialogWithoutDependencyInjection() throws Exception {

		//
		// A version of the test to use all of the real dialog internals of the
		// TaskRunner, which are usually replaced with test versions.
		//

		FastModalTask task = new FastModalTask();

		new TaskLauncher(task);

		waitForTasks(); // make sure we don't timeout
	}

	@Test
	public void testModalDialog_FastTask_NoDialog() throws Exception {

		FastModalTask task = new FastModalTask();

		launchTask(task);

		waitForTask();

		assertFalse(taskDialog.wasShown());
		assertSwingThreadBlockedForTask();
	}

	@Test
	public void testModalDialog_SlowTask_Dialog() throws Exception {
		SlowModalTask task = new SlowModalTask();

		launchTask(task);

		waitForTask();

		assertDialogShown();
		assertSwingThreadBlockedForTask();
	}

	@Test
	public void testNonModalDialog_FastTask_NoDialog() throws Exception {

		FastNonModalTask task = new FastNonModalTask();

		launchTask(task);

		waitForTask();

		assertFalse(taskDialog.wasShown());
		assertNoDialogShown();
	}

	@Test
	public void testNonModalDialog_SlowTask_Dialog() throws Exception {

		SlowNonModalTask task = new SlowNonModalTask();

		launchTask(task);

		waitForTask();

		assertDialogShown();
		assertSwingThreadFinishedBeforeTask();
	}

	/*
	 * Verifies that if the dialog cancel button is activated, the task is cancelled
	 */
	@Test
	public void testTaskCancel() throws Exception {
		CountDownLatch latch = new CountDownLatch(1);
		LatchedModalTask task = new LatchedModalTask(latch);
		launchTaskWithoutBlocking(task);

		taskDialog.doShow();
		latch.countDown();

		assertFalse(taskDialog.isCancelled());
		taskDialog.cancel();
		assertTrue(taskDialog.isCancelled());
	}

	/*
	 * Verifies that if the task does not allow cancellation, the cancel button on the GUI
	 * is disabled
	 */
	@Test
	public void testTaskNoCancel() throws Exception {
		SlowModalTask task = new SlowModalTask();
		launchTask(task);

		taskDialog.doShow();
		taskDialog.setCancelEnabled(false);

		waitForTask();

		assertFalse(taskDialog.isCancelEnabled());
	}
}
