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
package ghidra.framework.task.gui;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.JFrame;

import org.junit.*;

import docking.test.AbstractDockingTest;
import generic.concurrent.GThreadPool;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.framework.task.*;
import ghidra.framework.task.gui.taskview.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTaskGUITest extends AbstractDockingTest {

	private GenericDomainObjectDB domainObj;
	private GTaskManager taskMgr;
	private JFrame jFrame;
	private GTaskManagerPanel taskPanel;

	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(false);

		domainObj = new GenericDomainObjectDB(this);
		GThreadPool threadPool = GThreadPool.getSharedThreadPool("Test Thread Pool");
		taskMgr = new GTaskManager(domainObj, threadPool);
		taskPanel = new GTaskManagerPanel(taskMgr);
		taskPanel.setUseAnimations(false);
		jFrame = new JFrame("Test");
		jFrame.getContentPane().add(taskPanel);
		jFrame.pack();

		jFrame.setVisible(true);
	}

	@After
	public void tearDown() throws Exception {

		domainObj.release(this);
		jFrame.setVisible(false);
		waitForSwing();
	}

	@Test
	public void testGroupProgressBar() {
		assertNoProgress();
		pauseQ();
		scheduleTasks("First Tasks", 5);
		assertNoProgress();
		assertWaitingCount(5);
		assertRunningCount(0);

		runOneTask();
		assertWaitingCount(4);
		assertRunningCount(0);
		assertRunningGroupProgress(1, 5);

		scheduleTasks("More First Tasks", 2);
		assertRunningGroupProgress(1, 7);
		assertWaitingCount(6);
		assertRunningCount(0);

		runOneTask();
		assertRunningGroupProgress(2, 7);
		assertWaitingCount(5);
		assertRunningCount(0);

		runOneTask();
		assertRunningGroupProgress(3, 7);
		assertWaitingCount(4);
		assertRunningCount(0);

		runOneTask();
		assertRunningGroupProgress(4, 7);
		assertWaitingCount(3);
		assertRunningCount(0);

		runOneTask();
		assertRunningGroupProgress(5, 7);
		assertWaitingCount(2);
		assertRunningCount(0);

		runOneTask();
		assertRunningGroupProgress(6, 7);
		assertWaitingCount(1);
		assertRunningCount(0);

		runOneTask();
		assertRunningGroupProgress(7, 7);
		assertWaitingCount(0);
		assertRunningCount(0);

		runOneTask();
		assertNoProgress();
		assertWaitingCount(0);
		assertRunningCount(0);

		scheduleTasks("Second Tasks", 2);
		runOneTask();
		assertRunningGroupProgress(1, 2);
		assertWaitingCount(1);
		assertRunningCount(0);

	}

	@Test
	public void testTaskProgress() {
		AdvanceableTask task = new AdvanceableTask("Task");
		taskMgr.scheduleTask(task, 4, true);
		task.waitUntilRun();
		assertRunningGroupProgress(0, 1);
		assertTaskProgress(0, 4);
		task.advance();
		assertTaskProgress(1, 4);
		task.advance();
		assertTaskProgress(2, 4);
		task.advance();
		assertTaskProgress(3, 4);
		task.advance();
		assertWaitingCount(0);
		assertRunningCount(0);
	}

	@Test
	public void testBasicSchedulingPanel() {
		pauseQ();
		assertWaitingCount(0);
		assertRunningCount(0);

		SimpleTask task1 = new SimpleTask("Task1");
		GTaskGroup group = taskMgr.scheduleTask(task1, 10, true).getGroup();
		assertWaitingCount(1);
		assertRunningCount(0);
		assertWaitingTasks(task1);

		SimpleTask task2 = new SimpleTask("Task2");
		taskMgr.scheduleTask(task2, 5, true);
		assertWaitingCount(2);
		assertRunningCount(0);
		assertWaitingTasks(task2, task1);

		runOneTask();
		assertWaitingCount(1);
		assertRunningCount(0);
		assertWaitingTasks(task1);

		runOneTask();
		assertWaitingCount(0);
		assertRunningCount(0);
		assertRunningGroup(group);

		runOneTask();
		assertWaitingCount(0);
		assertRunningCount(0);

	}

	@Test
	public void testMultiGroupSchedulingPanel() {
		pauseQ();
		assertWaitingCount(0);
		assertRunningCount(0);

		SimpleTask task1 = new SimpleTask("Task1");
		GScheduledTask scheduleTask = taskMgr.scheduleTask(task1, 10, true);
		GTaskGroup group1 = scheduleTask.getGroup();
		assertWaitingCount(1);
		assertRunningCount(0);
		assertWaitingTasks(task1);

		SimpleTask task2 = new SimpleTask("Task2");
		taskMgr.scheduleTask(task2, 5, true);
		assertWaitingCount(2);
		assertRunningCount(0);
		assertWaitingTasks(task2, task1);
		assertWaitingGroups(group1);

		GTaskGroup group2 = new GTaskGroup("Group", true);
		SimpleTask task3 = new SimpleTask("Task3");
		SimpleTask task4 = new SimpleTask("Task4");
		group2.addTask(task3, 5);
		group2.addTask(task4, 6);
		taskMgr.scheduleTaskGroup(group2);

		assertWaitingCount(4);
		assertRunningCount(0);
		assertWaitingGroups(group1, group2);
		assertWaitingTasks(task2, task1, task3, task4);

		runOneTask();
		assertWaitingCount(3);
		assertRunningCount(0);
		assertWaitingGroups(group2);
		assertRunningGroup(group1);
		assertWaitingTasks(task1, task3, task4);

		runOneTask();
		assertWaitingCount(2);
		assertRunningCount(0);
		assertWaitingGroups(group2);
		assertRunningGroup(group1);
		assertWaitingTasks(task3, task4);

		runOneTask();
		assertWaitingCount(1);
		assertRunningCount(0);
		assertWaitingGroups();
		assertRunningGroup(group2);
		assertWaitingTasks(task4);

		runOneTask();
		assertWaitingCount(0);
		assertRunningCount(0);
		assertWaitingGroups();
		assertRunningGroup(group2);
		assertWaitingTasks();

		runOneTask();
		assertWaitingCount(0);
		assertRunningCount(0);
		assertWaitingGroups();
		assertWaitingTasks();
	}

	@Test
	public void testInsertHigherPriorityTask() {
		pauseQ();
		List<GTask> tasks = scheduleTasks("First Tasks", 2);
		assertWaitingCount(2);
		assertRunningCount(0);
		assertWaitingTasks(tasks.get(0), tasks.get(1));

		SimpleTask newTask = new SimpleTask("New Task");
		GScheduledTask scheduledTask = taskMgr.scheduleTask(newTask, 0, true);
		assertWaitingCount(3);
		assertRunningCount(0);
		assertWaitingTasks(newTask, tasks.get(0), tasks.get(1));
		assertWaitingGroups(scheduledTask.getGroup());
	}

	@Test
	public void testWaitingTask() {
		AdvanceableTask yieldingTask = new YieldingAdvanceableTask();

		taskMgr.scheduleTask(yieldingTask, 10, true);
		yieldingTask.waitUntilRun();
		yieldingTask.advance();

		// note: we must wait here to make sure that the task we schedule below does not get
		//       run before we expect
		yieldingTask.waitForWorkFinished(1);

		assertWaitingCount(0);
		assertRunningCount(1);

		AdvanceableTask highPriorityTask = new AdvanceableTask("High Priority Task");
		taskMgr.scheduleTask(highPriorityTask, 1, true);

		assertWaitingCount(1);
		assertRunningCount(1);
		assertRunningTasks(yieldingTask);
		assertWaitingTasks(highPriorityTask);

		yieldingTask.advance();
		highPriorityTask.waitUntilRun();

		assertWaitingCount(0);
		assertRunningCount(2);
		assertRunningTasks(yieldingTask, highPriorityTask);

		AbstractTaskInfo scheduledElement = getFirstTaskElement();
		GProgressBar progressBar = scheduledElement.getComponent().getProgressBar();
		assertEquals("WAITING FOR HIGHER PRIORITY TASKS!", progressBar.getMessage());
	}

	@Test
	public void testResultPanel() {
		pauseQ();

		taskMgr.scheduleTask(new SimpleTask("Task1"), 10, true);
		taskMgr.scheduleTask(new SimpleTask("Task2"), 10, true);
		taskMgr.scheduleTask(new SimpleTask("Task3"), 10, true);
		taskMgr.scheduleTask(new SimpleTask("Task4"), 10, false);

		assertResultListSize(0);
		runOneTask();
		assertResultListSize(1);
		runOneTask();
		assertResultListSize(2);
		resumeQ();
		waitForQ();

		runSwing(() -> taskPanel.showResultPanel(true));
		assertResultListSize(5);

	}

	@Test
	public void testInitializingGuiFromExistingState() {
		pauseQ();

		taskMgr.scheduleTask(new SimpleTask("Task1"), 10, true);
		taskMgr.scheduleTask(new SimpleTask("Task2"), 10, true);
		taskMgr.scheduleTask(new SimpleTask("Task3"), 10, true);
		taskMgr.scheduleTask(new SimpleTask("Task4"), 10, false);

		runOneTask();
		runOneTask();

		assertWaitingCount(2);
		assertRunningCount(0);

		assertResultListSize(2);

		closeAndReopenTaskManager();

		assertWaitingCount(2);
		assertRunningCount(0);
		assertResultListSize(2);
		List<GTaskResultInfo> resultList = getResultList();
		assertEquals("Task1", resultList.get(0).getResult().getDescription());
		assertEquals("Task2", resultList.get(1).getResult().getDescription());
	}

	@Test
	public void testInitializingGuiFromExistingStateWithDelayedAndRunningTasks() {
		AdvanceableTask yieldingTask = new YieldingAdvanceableTask();

		taskMgr.scheduleTask(yieldingTask, 10, true);
		yieldingTask.waitUntilRun();
		yieldingTask.advance();

		// note: we must wait here to make sure that the task we schedule below does not get
		//       run before we expect
		yieldingTask.waitForWorkFinished(1);

		AdvanceableTask highPriorityTask = new AdvanceableTask("High Priority Task");
		taskMgr.scheduleTask(highPriorityTask, 1, true);
		assertWaitingCount(1);
		assertWaitingTasks(highPriorityTask);
		assertRunningCount(1);
		assertRunningTasks(yieldingTask);

		yieldingTask.advance();

		assertWaitingCount(0);
		assertRunningCount(2);
		assertRunningTasks(yieldingTask, highPriorityTask);

		closeAndReopenTaskManager();

		assertWaitingCount(0);
		assertRunningCount(2);
		assertRunningTasks(yieldingTask, highPriorityTask);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void closeAndReopenTaskManager() {

		// not sure if these have to be separate; maybe it is this way in order to let the
		// swing queue process some events?
		runSwing(() -> jFrame.getContentPane().remove(taskPanel));

		runSwing(() -> {
			taskPanel = new GTaskManagerPanel(taskMgr);
			taskPanel.setUseAnimations(false);
			taskPanel.showResultPanel(true);
			jFrame.getContentPane().add(taskPanel);
			jFrame.validate();
		});
	}

	private void assertRunningGroup(GTaskGroup group) {
		List<AbstractTaskInfo> runningElements = getRunningTaskInfos();
		assertFalse("No Group running, but should be", runningElements.isEmpty());
		GTaskGroup runningGroup = runningElements.get(0).getGroup();
		assertEquals("Wrong group running", group, runningGroup);
	}

	private void assertRunningCount(int count) {
		waitForSwing();
		waitForCondition(() -> count == getRunningTasks().size());
	}

	private void assertWaitingCount(int count) {
		waitForSwing();
		waitForCondition(() -> count == getWaitingCount(), "Timed-out waiting for the 'wait count' to be " + count + ", but was " +
			getWaitingCount());
	}

	private int getWaitingCount() {
		List<GTask> waitingTasks = getWaitingTasks();
		return waitingTasks.size();
	}

	private AbstractTaskInfo getFirstTaskElement() {
		List<AbstractTaskInfo> runningList = new ArrayList<>(getRunningTaskInfos());
		return runningList.get(1);
	}

	private void assertWaitingTasks(GTask... tasks) {
		List<GTask> waitingTasks = getWaitingTasks();
		assertEquals("wrong number of waiting tasks", tasks.length, waitingTasks.size());
		for (int i = 0; i < tasks.length; i++) {
			assertEquals("Tasks in wrong order", tasks[i], waitingTasks.get(i));
		}
	}

	private void assertRunningTasks(GTask... tasks) {
		List<GTask> runningTasks = getRunningTasks();
		assertEquals("wrong number of running tasks", tasks.length, runningTasks.size());
		for (int i = 0; i < tasks.length; i++) {
			assertEquals("Tasks in wrong order", tasks[i], runningTasks.get(i));
		}
	}

	private void assertWaitingGroups(GTaskGroup... taskGroups) {
		List<GTaskGroup> waitingGroups = getWaitingGroups();
		assertEquals("wrong number of waiting groups", taskGroups.length, waitingGroups.size());
		for (int i = 0; i < taskGroups.length; i++) {
			assertEquals("Tasks in wrong order", taskGroups[i], waitingGroups.get(i));
		}
	}

	private List<GTask> getRunningTasks() {
		return getTasks(getRunningTaskInfos());
	}

	private List<GTask> getWaitingTasks() {
		return getTasks(getWaitingTaskInfos());
	}

	private List<GTaskGroup> getWaitingGroups() {
		List<GTaskGroup> groups = new ArrayList<>();
		List<AbstractTaskInfo> waitingInfos = getWaitingTaskInfos();
		for (AbstractTaskInfo info : waitingInfos) {
			if (info instanceof GroupInfo) {
				groups.add(info.getGroup());
			}
		}
		return groups;
	}

	private List<GTask> getTasks(List<AbstractTaskInfo> infoList) {
		List<GTask> taskList = new ArrayList<>();
		for (AbstractTaskInfo info : infoList) {
			if (info instanceof TaskInfo) {
				GScheduledTask scheduledTask = ((TaskInfo) info).getScheduledTask();
				taskList.add(scheduledTask.getTask());
			}
		}
		return taskList;
	}

	private void waitForQ() {
		while (taskMgr.isBusy()) {
			sleep(10);
		}
	}

	private void waitForRunningQ() {
		while (taskMgr.isRunning()) {
			sleep(10);
		}
	}

	private void resumeQ() {
		taskMgr.setSuspended(false);
	}

	private void runOneTask() {
		taskMgr.runNextTaskEvenWhenSuspended();
		waitForRunningQ();
	}

	private List<GTask> scheduleTasks(String baseName, int n) {
		List<GTask> tasks = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			SimpleTask task = new SimpleTask(baseName + "_" + i);
			tasks.add(task);
			taskMgr.scheduleTask(task, i * 10 + 10, true);
		}
		return tasks;
	}

	private void pauseQ() {
		taskMgr.setSuspended(true);
	}

	private void assertRunningGroupProgress(int progress, int max) {
		waitForSwing();
		List<AbstractTaskInfo> runningList = getRunningTaskInfos();
		AbstractTaskInfo first = runningList.get(0);
		ScheduledTaskPanel component = first.getComponent();
		GProgressBar bar = component.getProgressBar();
		assertEquals("checking progress value: ", progress, (int) bar.getProgress());
		assertEquals("checking max value: ", max, (int) bar.getMax());
	}

	private void assertNoProgress() {
		waitForSwing();
		List<AbstractTaskInfo> runningList = getRunningTaskInfos();
		assertTrue(runningList.isEmpty());
	}

	@SuppressWarnings("unchecked")
	private List<AbstractTaskInfo> getRunningTaskInfos() {
		TaskViewer taskViewer = (TaskViewer) getInstanceField("taskViewer", taskPanel);
		return new ArrayList<>(
			(Deque<AbstractTaskInfo>) getInstanceField("runningList", taskViewer));
	}

	@SuppressWarnings("unchecked")
	private List<AbstractTaskInfo> getWaitingTaskInfos() {
		TaskViewer taskViewer = (TaskViewer) getInstanceField("taskViewer", taskPanel);
		return new ArrayList<>(
			(Deque<AbstractTaskInfo>) getInstanceField("waitingList", taskViewer));
	}

	@SuppressWarnings("unchecked")
	private List<GTaskResultInfo> getResultList() {
		GTaskResultPanel resultPanel =
			(GTaskResultPanel) getInstanceField("resultPanel", taskPanel);
		CompletedTaskListModel model =
			(CompletedTaskListModel) getInstanceField("model", resultPanel);
		return (List<GTaskResultInfo>) getInstanceField("list", model);
	}

	private void assertResultListSize(int size) {
		waitForSwing();
		List<GTaskResultInfo> resultList = getResultList();
		assertEquals(size, resultList.size());
	}

	private void assertTaskProgress(int progress, int max) {
		waitForSwing();
		List<AbstractTaskInfo> runningList = getRunningTaskInfos();

		AbstractTaskInfo taskElement = runningList.get(runningList.size() - 1);
		ScheduledTaskPanel component = taskElement.getComponent();
		GProgressBar bar = component.getProgressBar();
		assertEquals("checking progress value: ", progress, (int) bar.getProgress());
		assertEquals("checking max value: ", max, (int) bar.getMax());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class YieldingAdvanceableTask extends AdvanceableTask {

		YieldingAdvanceableTask() {
			super("Low Priority Yielding Task");
		}

		@Override
		protected void doWork(final TaskMonitor monitor) {
			//
			// Unusual Code: We can't call taskMgr.waitForHigherPriorityTasks() without first
			// releasing the 'work finished' latch, as that will cause a deadlock.  So, we have
			// to release that lock, be still be able to block the advance() method so that the
			// test does not keep going until we let our 'higher priority task' get
			// scheduled.   So, signal that our work is done, but then wait for the sub-work
			// to be be scheduled.
			//
			debug(getName() + ": release workFinished latch early");
			workFinishedLatch.countDown();

			// WARNING!: this call is re-entrant and will block waiting for the 'work start' latch,
			// which only gets reset after we release the 'work finished' latch (like we had to
			// do above).
			debug(getName() + ": waiting for higher priority tasks");
			taskMgr.waitForHigherPriorityTasks();
			debug(getName() + ": done waiting");

			monitor.incrementProgress(1);
			debug(getName() + ": did some work");
		}
	}

	private class AdvanceableTask extends SimpleTask {
		private static final int DEFAULT_LOOP_COUNT = 4;

		protected CountDownLatch taskStartLatch = new CountDownLatch(1);
		protected CountDownLatch workStartLatch = new CountDownLatch(1);
		protected CountDownLatch workFinishedLatch = new CountDownLatch(1);

		private int loopCount = DEFAULT_LOOP_COUNT;

		private AtomicInteger workCount = new AtomicInteger();

		AdvanceableTask(String name) {
			super(name);
		}

		void advance() {
			//
			// Note: the subclass will release the 'workFinishedLatch' early, before work is 
			//       actually finished.  This means that the test may proceed and perform
			//       scheduling earlier than anticipated.
			//
			workStartLatch.countDown();
			try {
				workFinishedLatch.await(2, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				Assert.fail("Interrupted waiting for latch!");
			}
			workFinishedLatch = new CountDownLatch(1);
		}

		void waitUntilRun() {
			try {
				taskStartLatch.await(2, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		void waitForWorkFinished(int n) {
			waitForCondition(() -> workCount.get() == n, "Work iteration " + n + " never completed");
		}

		@Override
		public void run(UndoableDomainObject obj, TaskMonitor monitor) throws CancelledException {
			debug(getName() + ": Run called");
			monitor.initialize(loopCount);
			taskStartLatch.countDown();
			debug(getName() + ": Past start latch");

			for (int i = 0; i < loopCount; i++) {
				try {
					debug(getName() + ": Waiting for work latch");
					workStartLatch.await(2, TimeUnit.SECONDS);
					workStartLatch = new CountDownLatch(1);
					debug(getName() + ": past work latch, starting work");
					doWork(monitor);
					debug(getName() + ": Done work");
					workCount.incrementAndGet();
					workFinishedLatch.countDown();
				}
				catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
			super.run(obj, monitor);
			debug(getName() + ": Ending...");
		}

		protected void doWork(TaskMonitor monitor) {
			monitor.incrementProgress(1);
			debug(getName() + ": did some work");
		}

		protected void debug(String s) {
			// avoiding the logger, as it can buffer, which makes the output potentially 
			// out-of-order for multiple threads
			// Msg.debug(this, s);
			System.err.println("DEBUG " + s + " (GTaskGUITest.java:667)");
		}
	}

}
