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

import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingWorker;

import org.junit.Test;

import docking.test.AbstractDockingTest;
import sun.awt.AppContext;
import sun.swing.AccumulativeRunnable;

public class CachingSwingWorkerTest extends AbstractDockingTest {

	private static final int ITEM_COUNT = 10;

	@Test
	public void testSimpleThreadCase() throws InterruptedException {
		TestWorker worker = new TestWorker();

		MyThread r1 = new MyThread(0, worker);
		MyThread r2 = new MyThread(0, worker);
		MyThread r3 = new MyThread(10, worker);
		MyThread r4 = new MyThread(20, worker);

		worker.setDone();
		r1.join();
		r2.join();
		r3.join();
		r4.join();

		assertEquals("number of runs", 1, worker.getNumRuns());

		assertEquals(ITEM_COUNT, r1.size());
		assertEquals(ITEM_COUNT, r2.size());
		assertEquals(ITEM_COUNT, r3.size());
		assertEquals(ITEM_COUNT, r4.size());

	}

	@Test
	public void testSimpleSwingThreadCase() {

		disasbleTimerUsage();

		TestWorker worker = new TestWorker();
		worker.setTaskDialogDelay(0);

		ClientRunnable runnable = new ClientRunnable(worker);
		runSwing(runnable, false);

		TaskDialog dialog = waitForDialogComponent(null, TaskDialog.class, 2000);
		assertNotNull(dialog);

		worker.setDone();
		worker.get(TaskMonitorAdapter.DUMMY_MONITOR);

		waitForPostedSwingRunnables();
		assertTrue(!dialog.isVisible());
		assertEquals("number of runs", 1, worker.getNumRuns());

		assertEquals(ITEM_COUNT, runnable.size());
	}

	@Test
	public void testSwingAndAnotherThreadCase() throws InterruptedException {

		disasbleTimerUsage();

		TestWorker worker = new TestWorker();
		worker.setTaskDialogDelay(0);

		ClientRunnable runnable = new ClientRunnable(worker);
		runSwing(runnable, false);

		MyThread r1 = new MyThread(100, worker);

		TaskDialog dialog = waitForDialogComponent(null, TaskDialog.class, 2000);
		assertNotNull(dialog);

		worker.setDone();
		worker.get(TaskMonitorAdapter.DUMMY_MONITOR);
		r1.join();
		assertEquals(ITEM_COUNT, r1.size());

		waitForPostedSwingRunnables();
		assertTrue(!dialog.isVisible());
		assertEquals("number of runs", 1, worker.getNumRuns());

		assertEquals(ITEM_COUNT, runnable.size());
	}

	@Test
	public void testSwingAfterAnotherThreadCase() throws InterruptedException {

		disasbleTimerUsage();

		TestWorker worker = new TestWorker();
		worker.setTaskDialogDelay(0);

		MyThread r1 = new MyThread(0, worker);
		Thread.sleep(50);
		ClientRunnable runnable = new ClientRunnable(worker);
		runSwing(runnable, false);

		TaskDialog dialog = waitForDialogComponent(null, TaskDialog.class, 2000);
		assertNotNull(dialog);

		worker.setDone();
		worker.get(TaskMonitorAdapter.DUMMY_MONITOR);
		r1.join();
		assertEquals(ITEM_COUNT, r1.size());

		waitForPostedSwingRunnables();
		assertTrue(!dialog.isVisible());
		assertEquals("number of runs", 1, worker.getNumRuns());

		assertEquals(ITEM_COUNT, runnable.size());
	}

	@Test
	public void testCancelled() {
		TestWorker worker = new TestWorker();
		worker.setTaskDialogDelay(0);

		ClientRunnable runnable = new ClientRunnable(worker);
		runSwing(runnable, false);
		runSwing(runnable, false);

		TaskDialog dialog = waitForDialogComponent(null, TaskDialog.class, 2000);
		assertTrue(dialog.getTitle().contains("Test Worker"));
		assertNotNull(dialog);

		dialog.cancel();
		worker.get(TaskMonitorAdapter.DUMMY_MONITOR);

		waitForPostedSwingRunnables();
		assertTrue(!dialog.isVisible());
		assertEquals("number of runs", 1, worker.getNumRuns());

		assertTrue(worker.wasCancelled);

	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void disasbleTimerUsage() {
		AccumulativeRunnable<Runnable> nonTimerAccumulativeRunnable =
			new AccumulativeRunnable<Runnable>() {
				@Override
				protected void run(List<Runnable> args) {
					for (Runnable runnable : args) {
						runnable.run();
					}
				}
			};

		Object key = getInstanceField("DO_SUBMIT_KEY", SwingWorker.class);

		AppContext appContext = AppContext.getAppContext();
		appContext.put(key, nonTimerAccumulativeRunnable);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	class MyThread extends Thread {
		ClientRunnable runnable;

		MyThread(int delay, TestWorker worker) {
			runnable = new ClientRunnable(worker);
			try {
				Thread.sleep(delay);
			}
			catch (InterruptedException e) {
				// whatever
			}
			start();
		}

		@Override
		public void run() {
			runnable.run();
		}

		int size() {
			if (runnable == null) {
				return 0;
			}
			return runnable.size();
		}
	}

	class TestWorker extends CachingSwingWorker<List<String>> {
		private volatile boolean done = false;
		private int numRuns = 0;
		private volatile boolean wasCancelled = false;

		public TestWorker() {
			super("Test Worker", true);
		}

		@Override
		protected List<String> runInBackground(TaskMonitor monitor) {
			monitor.initialize(ITEM_COUNT);
			numRuns++;
			List<String> list = new ArrayList<String>();
			int count = 0;
			while (!done || count < ITEM_COUNT) {
				if (monitor.isCancelled()) {
					wasCancelled = true;
					break;
				}

				if (count < ITEM_COUNT) {
					String message = "line " + count;
					list.add(message);
					monitor.setProgress(count);
					monitor.setMessage(message);
				}

				count++;

				try {
					Thread.sleep(10);
				}
				catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				if (count > 600) {
					list.add("timeout");
					break;
				}
			}

			return list;
		}

		void setDone() {
			done = true;
		}

		boolean wasCancelled() {
			return wasCancelled;
		}

		int getNumRuns() {
			return numRuns;
		}
	}

	class ClientRunnable implements Runnable {
		List<String> result;
		private TestWorker worker;

		ClientRunnable(TestWorker worker) {
			this.worker = worker;
		}

		public int size() {
			return result == null ? 0 : result.size();
		}

		@Override
		public void run() {
			result = worker.get(TaskMonitorAdapter.DUMMY_MONITOR);
		}
	}
}
