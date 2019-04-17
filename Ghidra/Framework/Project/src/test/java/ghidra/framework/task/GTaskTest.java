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
package ghidra.framework.task;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.*;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.*;

import generic.concurrent.GThreadPool;
import generic.test.AbstractGenericTest;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTaskTest extends AbstractGenericTest {

	private GenericDomainObjectDB domainObject;
	private GTaskManager gTaskManager;
	private List<GTaskResult> taskResults = new ArrayList<GTaskResult>();
	private GTaskListener listener = new GTaskListenerAdapter() {
		@Override
		public void taskCompleted(GScheduledTask task, GTaskResult result) {
			taskResults.add(result);
		}
	};

	public GTaskTest() {
		super();
	}

	@Before
	public void setUp() throws IOException {
		domainObject = new GenericDomainObjectDB(this);
		GThreadPool threadPool = GThreadPool.getSharedThreadPool("Test Thread Pool");
		gTaskManager = new GTaskManager(domainObject, threadPool);
		gTaskManager.addTaskListener(listener);
	}

	@After
	public void tearDown() {
		domainObject.release(this);
	}

	@Test
	public void testRunOneTask() {
		SimpleTask task = new SimpleTask("Task 1");
		gTaskManager.scheduleTask(task, 5, true);
		waitForTaskManager();
		assertTrue("Task did not run!", task.didRun());
		assertTrue(domainObject.currentTransaction == null);
		assertTrue(domainObject.transactionsList.size() == 1);
		assertEquals("Task 1", domainObject.transactionsList.get(0));
	}

	@Test
	public void testRunTwoTasksSameTransaction() {
		LatchedTask task1 = new LatchedTask("Task 1");
		SimpleTask task2 = new SimpleTask("Task 2");
		gTaskManager.scheduleTask(task1, 1, true);
		gTaskManager.scheduleTask(task2, 2, true);
		task1.latch.countDown();
		waitForTaskManager();
		assertTrue("Task did not run!", task1.didRun());
		assertTrue("Task did not run!", task2.didRun());
		assertTrue(domainObject.currentTransaction == null);
		assertTrue(domainObject.transactionsList.size() == 1);
		assertEquals("Task 1", domainObject.transactionsList.get(0));
	}

	@Test
	public void testRunTwoTaskDifferentTransactions() {
		LatchedTask task1 = new LatchedTask("Task 1");
		SimpleTask task2 = new SimpleTask("Task 2");
		gTaskManager.scheduleTask(task1, 1, true);
		gTaskManager.scheduleTask(task2, 2, false);
		task1.latch.countDown();
		waitForTaskManager();
		assertTrue("Task did not run!", task1.didRun());
		assertTrue("Task did not run!", task2.didRun());
		assertTrue(domainObject.currentTransaction == null);
		assertTrue(domainObject.transactionsList.size() == 2);
		assertEquals("Task 1", domainObject.transactionsList.get(0));
		assertEquals("Task 2", domainObject.transactionsList.get(1));
	}

	@Test
	public void testNewTransactionGroupWithoutNewTransaction() {
		LatchedTask task1 = new LatchedTask("Task 1");
		gTaskManager.scheduleTask(task1, 1, true);
		GTaskGroup group = new GTaskGroup("Group", false);
		SimpleTask task2 = new SimpleTask("Task 2");
		group.addTask(task2, 4);
		gTaskManager.scheduleTaskGroup(group);
		task1.latch.countDown();
		waitForTaskManager();
		assertTrue("Task did not run!", task1.didRun());
		assertTrue("Task did not run!", task2.didRun());
		assertTrue(domainObject.currentTransaction == null);
		assertEquals(1, domainObject.transactionsList.size());
		assertEquals("Task 1", domainObject.transactionsList.get(0));

	}

	@Test
	public void testNewTransactionGroupWithNewTransaction() {
		LatchedTask task1 = new LatchedTask("Task 1");
		gTaskManager.scheduleTask(task1, 1, true);

		GTaskGroup group = new GTaskGroup("Group", true);
		SimpleTask task2 = new SimpleTask("Task 2");
		group.addTask(task2, 4);
		gTaskManager.scheduleTaskGroup(group);
		task1.latch.countDown();
		waitForTaskManager();
		assertTrue("Task did not run!", task1.didRun());
		assertTrue("Task did not run!", task2.didRun());
		assertTrue(domainObject.currentTransaction == null);
		assertTrue(domainObject.transactionsList.size() == 2);
		assertEquals("Task 1", domainObject.transactionsList.get(0));
		assertEquals("Group", domainObject.transactionsList.get(1));

	}

	@Test
	public void testSuspendBeforeSchedulingTasks() {
		gTaskManager.setSuspended(true);
		SimpleTask task = new SimpleTask("Task 1");
		gTaskManager.scheduleTask(task, 5, true);
		waitForRunningTaskManager();
		assertTrue(!task.didRun);
		gTaskManager.setSuspended(false);
		waitForTaskManager();
		assertTrue(task.didRun);
	}

	@Test
	public void testSuspendWhileRunningTasks() {
		LatchedTask task = new LatchedTask("Task 1");
		SimpleTask task2 = new SimpleTask("test 2");
		gTaskManager.scheduleTask(task, 5, true);
		gTaskManager.scheduleTask(task2, 10, true);

		gTaskManager.setSuspended(true);
		gTaskManager.scheduleTask(task, DEFAULT_WAIT_DELAY, BATCH_MODE);

		assertTrue(!task.didRun());
		task.latch.countDown();
		waitForRunningTaskManager();
		assertTrue(task.didRun());
		assertTrue(!task2.didRun());
		gTaskManager.setSuspended(false);
		waitForTaskManager();
		assertTrue(task2.didRun());
	}

	@Test
	public void testIsBusy() {
		assertTrue(!gTaskManager.isBusy());
		LatchedTask task = new LatchedTask("Task 1");
		gTaskManager.scheduleTask(task, 3, true);
		assertTrue(gTaskManager.isBusy());
		assertTrue(gTaskManager.isRunning());
		gTaskManager.setSuspended(true);
		gTaskManager.scheduleTask(new SimpleTask("Task 2"), 4, true);
		task.latch.countDown();
		waitForRunningTaskManager();
		assertTrue(gTaskManager.isBusy());
		gTaskManager.scheduleTask(new SimpleTask("Task 3"), 4, false);
		gTaskManager.runNextTaskEvenWhenSuspended();
		waitForRunningTaskManager();
		assertTrue(gTaskManager.isBusy());
		gTaskManager.runNextTaskEvenWhenSuspended();
		waitForRunningTaskManager();
		assertTrue(!gTaskManager.isBusy());
	}

	@Test
	public void testWaitForHigherPriorityTasks() {
		LatchedTask task = new LatchedTask("Task 1");
		gTaskManager.scheduleTask(task, 10, true);
		gTaskManager.scheduleTask(new YieldingTask("Task 2"), 10, true);
		gTaskManager.scheduleTask(new SimpleTask("Task 3"), 1, true);
		gTaskManager.scheduleTask(new SimpleTask("Task 4"), 2, true);
		gTaskManager.scheduleTask(new SimpleTask("Task 5"), 11, true);

		task.latch.countDown();
		waitForTaskManager();

		assertEquals(5, taskResults.size());
		assertEquals("Task 1", taskResults.get(0).getDescription());
		assertEquals("Task 3", taskResults.get(1).getDescription());
		assertEquals("Task 4", taskResults.get(2).getDescription());
		assertEquals("Task 2", taskResults.get(3).getDescription());
		assertEquals("Task 5", taskResults.get(4).getDescription());

	}

	@Test
	public void testSuspendWhileYielding() {
		LatchedTask task = new LatchedTask("Task 1");
		gTaskManager.scheduleTask(task, 10, true);
		gTaskManager.scheduleTask(new YieldingTask("Task 2"), 10, true);
		gTaskManager.scheduleTask(new SimpleTask("Task 3"), 2, true);
		gTaskManager.scheduleTask(new SimpleTask("Task 4"), 2, true);
		gTaskManager.scheduleTask(new SimpleTask("Task 5"), 11, true);

		gTaskManager.setSuspended(true);
		task.latch.countDown();
		waitForRunningTaskManager();

		assertEquals(1, taskResults.size());
		assertEquals("Task 1", taskResults.get(0).getDescription());
		gTaskManager.setSuspended(false);

		waitForTaskManager();
		assertEquals(5, taskResults.size());
		assertEquals("Task 1", taskResults.get(0).getDescription());
		assertEquals("Task 3", taskResults.get(1).getDescription());
		assertEquals("Task 4", taskResults.get(2).getDescription());
		assertEquals("Task 2", taskResults.get(3).getDescription());
		assertEquals("Task 5", taskResults.get(4).getDescription());

	}

	@Test
	public void testSuspendAndSingleSteppingWhileYielding() {
		LatchedTask task = new LatchedTask("Task 1");
		gTaskManager.scheduleTask(task, 10, true);
		gTaskManager.scheduleTask(new YieldingTask("Task 2"), 10, true);
		gTaskManager.scheduleTask(new SimpleTask("Task 3"), 2, true);
		gTaskManager.scheduleTask(new SimpleTask("Task 4"), 3, true);
		gTaskManager.scheduleTask(new SimpleTask("Task 5"), 11, true);

		gTaskManager.setSuspended(true);
		task.latch.countDown();
		waitForRunningTaskManager();

		assertEquals(1, taskResults.size());
		assertEquals("Task 1", taskResults.get(0).getDescription());

		gTaskManager.runNextTaskEvenWhenSuspended();
		waitForRunningTaskManager();
		assertEquals(2, taskResults.size());
		assertEquals("Task 3", taskResults.get(1).getDescription());

		gTaskManager.runNextTaskEvenWhenSuspended();
		waitForRunningTaskManager();
		assertEquals(3, taskResults.size());
		assertEquals("Task 4", taskResults.get(2).getDescription());

		gTaskManager.runNextTaskEvenWhenSuspended();
		waitForRunningTaskManager();
		assertEquals(4, taskResults.size());
		assertEquals("Task 2", taskResults.get(3).getDescription());

		gTaskManager.runNextTaskEvenWhenSuspended();
		waitForRunningTaskManager();
		assertEquals(5, taskResults.size());
		assertEquals("Task 5", taskResults.get(4).getDescription());

		gTaskManager.runNextTaskEvenWhenSuspended();
		waitForRunningTaskManager();
		assertEquals(5, taskResults.size());

	}

	@Test
	public void testPriority() {

		gTaskManager.setSuspended(true);
		gTaskManager.scheduleTask(new SimpleTask("Test 1"), 3, true);
		gTaskManager.scheduleTask(new SimpleTask("Test 2"), 1, true);
		gTaskManager.scheduleTask(new SimpleTask("Test 3"), 2, true);
		gTaskManager.setSuspended(false);
		waitForTaskManager();
		assertEquals("Test 2", taskResults.get(0).getDescription());
		assertEquals("Test 3", taskResults.get(1).getDescription());
		assertEquals("Test 1", taskResults.get(2).getDescription());
	}

	@Test
	public void testCancelTask() {
		LatchedTask task1 = new LatchedTask("Task 1");
		SimpleTask task2 = new SimpleTask("Task 2");
		gTaskManager.scheduleTask(task1, 1, true);
		gTaskManager.scheduleTask(task2, 2, true);
		cancelCurrentTask();
		task1.latch.countDown();
		waitForTaskManager();
		assertTrue("Task was not cancelled!", !task1.didRun());
		assertTrue("Task did not run!", task2.didRun());
	}

	@Test
	public void testCancelGroup() {
		LatchedTask task1 = new LatchedTask("Task 1");
		SimpleTask task2 = new SimpleTask("Task 2");
		gTaskManager.scheduleTask(task1, 1, true);
		gTaskManager.scheduleTask(task2, 2, true);
		cancelCurrentGroup();
		task1.latch.countDown();
		waitForTaskManager();
		assertTrue("Running Task was not cancelled!", !task1.didRun());
		assertTrue("Waiting Task was not cancelled!", !task2.didRun());
	}

	@Test
	public void testCancelAll() {
		LatchedTask task1 = new LatchedTask("Task 1");
		SimpleTask task2 = new SimpleTask("Task 2");
		gTaskManager.scheduleTask(task1, 1, true);
		gTaskManager.scheduleTask(task2, 2, true);

		GTaskGroup group = new GTaskGroup("Group", true);
		SimpleTask task3 = new SimpleTask("Task 3");
		SimpleTask task4 = new SimpleTask("Task 4");
		group.addTask(task3, 4);
		group.addTask(task4, 4);
		gTaskManager.scheduleTaskGroup(group);

		gTaskManager.cancelAll();

		task1.latch.countDown();
		waitForTaskManager();
		assertTrue("Running Task was not cancelled!", !task1.didRun());
		assertTrue("Waiting Task was not cancelled!", !task2.didRun());
		assertTrue("Running Task was not cancelled!", !task3.didRun());
		assertTrue("Waiting Task was not cancelled!", !task4.didRun());

		List<GTaskResult> results = gTaskManager.getTaskResults();
		assertEquals(4, results.size());
		for (GTaskResult gTaskResult : results) {
			assertTrue(gTaskResult.wasCancelled());
		}
	}

	@Test
	public void testAddingTaskByGroupNameToRunningGroup() {
		LatchedTask task1 = new LatchedTask("Task 1");
		gTaskManager.scheduleTask(task1, 10, "GROUP1");
		gTaskManager.scheduleTask(new SimpleTask("Task 2"), 20, "GROUP1");
		assertTrue(domainObject.transactionsList.size() == 0);
		task1.latch.countDown();
		waitForTaskManager();
		assertTrue(domainObject.transactionsList.size() == 1);
		assertEquals("GROUP1", domainObject.transactionsList.get(0));
		List<GTaskResult> results = gTaskManager.getTaskResults();
		assertEquals(2, results.size());
	}

	@Test
	public void testAddingTaskByGroupNameToWaitingGroup() {
		LatchedTask task1 = new LatchedTask("Task 1");
		gTaskManager.scheduleTask(task1, 10, "GROUP1");

		GTaskGroup group = new GTaskGroup("GROUP2", true);
		SimpleTask task3 = new SimpleTask("Task 3");
		SimpleTask task4 = new SimpleTask("Task 4");
		group.addTask(task3, 10);
		group.addTask(task4, 10);
		gTaskManager.scheduleTaskGroup(group);

		gTaskManager.scheduleTask(new SimpleTask("Task 5"), 20, "GROUP2");

		List<GTaskGroup> scheduledGroups = gTaskManager.getScheduledGroups();
		assertEquals(1, scheduledGroups.size());
		assertEquals(3, scheduledGroups.get(0).getTasks().size());

		task1.latch.countDown();
		waitForTaskManager();
		assertTrue(domainObject.transactionsList.size() == 2);
		assertEquals("GROUP1", domainObject.transactionsList.get(0));
		assertEquals("GROUP2", domainObject.transactionsList.get(1));
		List<GTaskResult> results = gTaskManager.getTaskResults();
		assertEquals(4, results.size());
	}

	@Test
	public void testAddingTaskByGroupNameToNonExistingGroup() {
		LatchedTask task1 = new LatchedTask("Task 1");
		gTaskManager.scheduleTask(task1, 10, "GROUP1");

		gTaskManager.scheduleTask(new SimpleTask("Task 5"), 20, "GROUP2");

		List<GTaskGroup> scheduledGroups = gTaskManager.getScheduledGroups();
		assertEquals(1, scheduledGroups.size());
		assertEquals(1, scheduledGroups.get(0).getTasks().size());

		task1.latch.countDown();
		waitForTaskManager();
		assertTrue(domainObject.transactionsList.size() == 2);
		assertEquals("GROUP1", domainObject.transactionsList.get(0));
		assertEquals("GROUP2", domainObject.transactionsList.get(1));
		List<GTaskResult> results = gTaskManager.getTaskResults();
		assertEquals(2, results.size());
	}

	@Test
	public void testExceptionInTaskListenerTaskCompleted() {

		// disable printing of exception below
		Logger logger = LogManager.getLogger(GTaskManager.class);
		Configurator.setLevel(logger.getName(), Level.OFF);

		gTaskManager.addTaskListener(new GTaskListenerAdapter() {
			@Override
			public void taskCompleted(GScheduledTask task, GTaskResult result) {
				throw new RuntimeException("Test Exception");
			}
		});

		gTaskManager.scheduleTask(new SimpleTask("Task 5"), 20, true);

		// this is testing that the exception does cause the taskManager to timeout still busy
		waitForTaskManager();

		Configurator.setLevel(logger.getName(), Level.DEBUG);
	}

	@Test
	public void testExceptionInTaskListenerTaskStarted() {

		// disable printing of exception below
		Logger logger = LogManager.getLogger(GTaskManager.class);
		Configurator.setLevel(logger.getName(), Level.OFF);

		gTaskManager.addTaskListener(new GTaskListenerAdapter() {
			@Override
			public void taskStarted(GScheduledTask task) {
				throw new RuntimeException("Test Exception");
			}
		});

		gTaskManager.scheduleTask(new SimpleTask("Task 5"), 20, true);

		// this is testing that the exception does cause the taskManager to timeout still busy
		waitForTaskManager();

		Configurator.setLevel(logger.getName(), Level.DEBUG);
	}

	private void cancelCurrentTask() {
		GScheduledTask runningTask = gTaskManager.getRunningTask();
		runningTask.getTaskMonitor().cancel();
	}

	private void cancelCurrentGroup() {
		gTaskManager.cancelRunningGroup(gTaskManager.getCurrentGroup());
	}

	private void waitForTaskManager() {
		assertTrue(gTaskManager.waitWhileBusy(1000));
		assertFalse(gTaskManager.isBusy());
	}

	private void waitForRunningTaskManager() {
		while (gTaskManager.isRunning()) {
			sleep(10);
		}
	}

	private class LatchedTask extends SimpleTask {
		CountDownLatch latch = new CountDownLatch(1);

		LatchedTask(String name) {
			super(name);
		}

		@Override
		public void run(UndoableDomainObject obj, TaskMonitor monitor) throws CancelledException {
			try {
				if (!latch.await(2, TimeUnit.SECONDS)) {
					Assert.fail("Latch await expired!");
				}
			}
			catch (InterruptedException e) {
				Assert.fail("Did not expect Interrupted Exception");
			}
			monitor.checkCanceled();
			super.run(obj, monitor);
		}
	}

	private class YieldingTask extends SimpleTask {
		YieldingTask(String name) {
			super(name);
		}

		@Override
		public void run(UndoableDomainObject obj, TaskMonitor monitor) throws CancelledException {
			GTaskManager taskManager = GTaskManagerFactory.getTaskManager(obj);
			taskManager.waitForHigherPriorityTasks();
			super.run(obj, monitor);
		}

	}
}
