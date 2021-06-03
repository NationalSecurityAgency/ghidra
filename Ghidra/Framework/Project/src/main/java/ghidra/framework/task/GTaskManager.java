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

import generic.concurrent.GThreadPool;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/** 
 * Class for managing a queue of tasks to be executed, one at a time, in priority order.  All the
 * tasks pertain to an UndoableDomainObject and transactions are created on the UndoableDomainObject
 * so that tasks can operate on them.
 * <P>
 * Tasks are organized into groups such that all tasks in a group will be completed before the
 * tasks in the next group, regardless of priority.  Within a group, task are ordered first by
 * priority and then by the order in which they were added to the group. Groups are executed 
 * in the order that they are scheduled.
 * <P>
 * All tasks within the same group are executed within the same transaction on the
 * UndoableDomainObject.  When all the tasks within a group are completed, the transaction is closed
 * unless there is another group scheduled and that group does not specify that it should run in its
 * own transaction.
 * <P>
 * <U>Suspending:</U><BR>
 * The GTaskManager can be suspended.  When suspended, any currently running task will continue to
 * run, but no new or currently scheduled tasks will be executed until the GTaskManager is resumed.
 * There is a special method, {@link #runNextTaskEvenWhenSuspended()}, that will run the next scheduled task
 * even if the GTaskManager is suspended.
 * <P>
 * <U>Yielding to Other Tasks:</U><BR>
 * While running, a GTask can call the method {@link #waitForHigherPriorityTasks()} on the GTaskManager, 
 * which will cause the the GTaskManager to run scheduled tasks (within the same group) that are 
 * a higher priority than the running task, effectively allowing the running task to yield until all
 * higher priority tasks are executed.
 * 
 * @see GTask
 * @see GTaskGroup
 */
public class GTaskManager {

	private static final int MAX_RESULTS = 100;

	private UndoableDomainObject domainObject;
	private SortedSet<GScheduledTask> priorityQ = new TreeSet<GScheduledTask>();
	private Deque<GTaskGroup> taskGroupList = new LinkedList<GTaskGroup>();
	private GThreadPool threadPool;

	// Note: every public method in this class should be locked; therefore, private methods don't
	// require locking.
	private ReentrantLock lock = new ReentrantLock(false);
	private Condition notBusy = lock.newCondition();
	private Condition isBusy = lock.newCondition();

	private GScheduledTask runningTask = null;
	private GTaskGroup runningGroup = null;

	private boolean suspended;

	private Integer currentGroupTransactionID;

	private GTaskListener taskListener = null;
	private Deque<GScheduledTask> delayedTaskStack = new ArrayDeque<GScheduledTask>();
	private Queue<GTaskResult> results = new ArrayDeque<GTaskResult>();

	/**
	 * Creates a new GTaskManager for an UndoableDomainObject
	 * @param undoableDomainObject the domainObject that tasks scheduled in this GTaskManager will
	 * operate upon.
	 * @param threadPool the GThreadPool that will provide the threads that will be used to run 
	 * tasks in this GTaskManager.
	 */
	public GTaskManager(UndoableDomainObject undoableDomainObject, GThreadPool threadPool) {
		this.domainObject = undoableDomainObject;
		this.threadPool = threadPool;

		domainObject.addCloseListener(new DomainObjectClosedListener() {
			@Override
			public void domainObjectClosed() {
				GTaskManagerFactory.domainObjectClosed(domainObject);
				domainObject = null;
			}
		});
	}

	/**
	 * Schedules a task to be run by this TaskManager. Tasks are run one at a time.
	 * 
	 * @param task the task to be run.
	 * @param priority the priority of the task.  Lower numbers are run before higher numbers.
	 * @param useCurrentGroup. If true, this task will be rolled into the current transaction group
	 * 							if one exists.  If false, any open transaction 
	 * 							will be closed and a new transaction will be opened before 
	 * 							this task is run.
	 */
	public GScheduledTask scheduleTask(GTask task, int priority, boolean useCurrentGroup) {
		GScheduledTask newTask;
		lock.lock();
		try {
			// if there is a current group running and this task can use the current group
			// add it to the current running group
			if (useCurrentGroup && runningGroup != null) {
				newTask = runningGroup.doAddTask(task, priority);
				priorityQ.add(newTask);
				notifyTaskScheduled(newTask);
			}
			// else if we can't use the current group or there is no groups at all
			// create a new group
			else if (taskGroupList.isEmpty() || !useCurrentGroup) {
				GTaskGroup group = new GTaskGroup(task.getName(), true);
				newTask = group.doAddTask(task, priority);
				taskGroupList.add(group);
				notifyTaskGroupScheduled(group);
			}
			// else add it to the first group  (can only happen if queue is paused)
			else {
				GTaskGroup group = taskGroupList.getFirst();
				newTask = group.doAddTask(task, priority);
				notifyTaskScheduled(newTask);
			}
			isBusy.signal();
			runNextTaskIfNotBusyOrSuspended();
		}
		finally {
			lock.unlock();
		}
		return newTask;
	}

	/**
	 * Schedules a task to be run by this TaskManager within the group with the given group name.
	 * If a group already exists with the given name(either currently running or waiting), the task
	 * will be added to that group. Otherwise, a new group will be created with the given group name
	 * and the task will be placed in that group.
	 * 
	 * @param task the task to be run.
	 * @param priority the priority of the task.  Lower numbers are run before higher numbers.
	 * @param groupName. The name of the group that the task will be added to.
	 */
	public void scheduleTask(GTask task, int priority, String groupName) {
		lock.lock();
		try {
			if (runningGroup != null && runningGroup.getDescription().equals(groupName)) {
				scheduleTask(task, priority, true);
				return;
			}
			for (GTaskGroup group : taskGroupList) {
				if (group.getDescription().equals(groupName)) {
					GScheduledTask newTask = group.doAddTask(task, priority);
					notifyTaskScheduled(newTask);
					runNextTaskIfNotBusyOrSuspended();
					return;
				}
			}
			GTaskGroup gTaskGroup = new GTaskGroup(groupName, true);
			gTaskGroup.addTask(task, priority);
			taskGroupList.add(gTaskGroup);
			notifyTaskGroupScheduled(gTaskGroup);
			isBusy.signal();
			runNextTaskIfNotBusyOrSuspended();
		}
		finally {
			lock.unlock();
		}

	}

	/**
	 * Schedules a task group to run.  Task groups are run in the order they are scheduled. They 
	 * have the option of being executed in the current transaction (if it exists) or starting
	 * a new transaction.
	 * 
	 * @param group the TaskGroup to be scheduled.
	 */
	public void scheduleTaskGroup(GTaskGroup group) {
		group.setScheduled();
		lock.lock();
		try {
			taskGroupList.add(group);
			notifyTaskGroupScheduled(group);
			isBusy.signal();
			runNextTaskIfNotBusyOrSuspended();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Sets the suspended state of this task queue.  While suspended, this task manager will not
	 * start any new tasks in its queue.  Any currently running task will continue to run.
	 * 
	 * @param b true to suspend this manager, false to resume executing new tasks.
	 */
	public void setSuspended(boolean b) {
		lock.lock();
		try {
			suspended = b;
			runNextTaskIfNotBusyOrSuspended();
			if (!suspended) {
				wakeUpWaitingThread();
			}
			notifySuspendedStateChanged();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * This method will cause the next scheduled task to run even though the task manager is
	 * suspended.  Calling this method while the queue is not suspended has no effect because
	 * if not suspended, it will be busy (or have nothing to do)
	 */
	public void runNextTaskEvenWhenSuspended() {
		lock.lock();
		try {
			runNextTaskIfNotBusy();
			wakeUpWaitingThread();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Adds a GTaskListener to be notified as tasks are completed.
	 * @param listener the listener to add
	 */
	public void addTaskListener(GTaskListener listener) {
		lock.lock();
		try {
			if (taskListener == null) {
				taskListener = listener;
			}
			else {
				taskListener = new MulticastTaskListener(taskListener, listener);
			}
			listener.initialize();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Removes the given GTaskListener from this queue. 
	 * @param listener the listener to remove.
	 */
	public void removeTaskListener(GTaskListener listener) {
		lock.lock();
		try {
			if (taskListener instanceof MulticastTaskListener) {
				taskListener = ((MulticastTaskListener) taskListener).removeListener(listener);
			}
			else if (taskListener == listener) {
				taskListener = null;
			}
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns true if this manager is running a task, or if suspended has additional tasks queued.
	 * @return  true if this manager is running a task, or if suspended has additional tasks queued.
	 */
	public boolean isBusy() {
		lock.lock();
		try {
			if (runningTask != null) {
				return true;
			}
			if (!priorityQ.isEmpty()) {
				return true;
			}
			if (!taskGroupList.isEmpty()) {
				return true;
			}
			return false;
		}
		finally {
			lock.unlock();
		}
	}

	public boolean waitWhileBusy(long timeoutMillis) {
		lock.lock();
		try {
			while (isBusy()) {
				try {
					return notBusy.await(timeoutMillis, TimeUnit.MILLISECONDS);
				}
				catch (InterruptedException e) {
					// ignore and loop
				}
			}
		}
		finally {
			lock.unlock();
		}
		return true;
	}

	public boolean waitUntilBusy(long timeoutMillis) {
		lock.lock();
		try {
			while (!isBusy()) {
				try {
					return isBusy.await(timeoutMillis, TimeUnit.MILLISECONDS);
				}
				catch (InterruptedException e) {
					// ignore and loop
				}
			}
		}
		finally {
			lock.unlock();
		}
		return true;
	}

	/**
	 * Returns true if this manager is currently running a task. If not suspended, a GTaskManager
	 * will always be executing a task as long as there are tasks to execute.  If suspended, a
	 * GTaskManager may have tasks scheduled, but may not be currently executing one.
	 * @return true if this manager is currently running a task.
	 */
	public boolean isRunning() {
		lock.lock();
		try {
			return runningTask != null;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * This methods is for currently running tasks to suspend and allow higher priority tasks 
	 * (within the same task group) to complete before continuing.  If called by any thread other
	 * than the thread that is currently executing a task for this queue, an exception will be 
	 * thrown.
	 * @throws IllegalStateException if this method is called from any thread not currently 
	 * executing the current task for this queue.
	 */
	public void waitForHigherPriorityTasks() {
		lock.lock();
		try {
			if (runningTask == null) {
				return;
			}
			if (!runningTask.isRunningInCurrentThread()) {
				throw new IllegalStateException(
					"Can only call this method from a currently running task");
			}
			int currentPriority = runningTask.getPriority();

			while (!priorityQ.isEmpty()) {
				GScheduledTask nextTask = priorityQ.first();
				if (nextTask.getPriority() >= currentPriority) {
					break;
				}
				delayedTaskStack.push(runningTask);
				runningTask.getTaskMonitor().setMessage("WAITING FOR HIGHER PRIORITY TASKS!");
				if (suspended) {
					doWait();
				}
				runningTask = nextTask;
				priorityQ.remove(nextTask);
				lock.unlock();
				GTaskRunnable runnable = new GTaskRunnable(nextTask);
				runnable.run();
				lock.lock();
				runningTask = delayedTaskStack.pop();
			}
		}
		finally {
			lock.unlock();
		}

	}

	/**
	 * Returns a list of the most recent GTaskResults.  The TaskManager only keeps the most recent
	 * N GTaskResults.
	 * @return the list of the most recent GTaskResults.
	 */
	public List<GTaskResult> getTaskResults() {
		lock.lock();
		try {
			return new ArrayList<GTaskResult>(results);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns a list of scheduled tasks for the currently running group.
	 * @return a list of scheduled tasks for the currently running group.
	 */
	public List<GScheduledTask> getScheduledTasks() {
		lock.lock();
		try {
			return new ArrayList<GScheduledTask>(priorityQ);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns a list of Tasks that are currently waiting for higher priority tasks.
	 * @return a list of Tasks that are currently waiting for higher priority tasks.
	 */
	public List<GScheduledTask> getDelayedTasks() {
		lock.lock();
		try {
			return new ArrayList<GScheduledTask>(delayedTaskStack);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns the currently running task, or null if no task is running.
	 * @return the currently running task;
	 */
	public GScheduledTask getRunningTask() {
		lock.lock();
		try {
			return runningTask;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns the currently running group, or null if no group is running.
	 * @return the currently running group, or null if no group is running.
	 */
	public GTaskGroup getCurrentGroup() {
		lock.lock();
		try {
			return runningGroup;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns a list of Groups that are waiting to run.
	 * @return a list of Groups that are waiting to run.
	 */
	public List<GTaskGroup> getScheduledGroups() {
		lock.lock();
		try {
			return new ArrayList<GTaskGroup>(taskGroupList);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns true if this GTaskManager is currently suspended. 
	 * @return true if this GTaskManager is currently suspended. 
	 */
	public boolean isSuspended() {
		lock.lock();
		try {
			return suspended;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Cancels all tasks in the currently running group.  Tasks in the group that have not yet started
	 * will never run and will immediately be put into the TaskResults list.  The TaskMonitor for
	 * the currently running task will be cancelled, but the task will continue to run until it
	 * checks the monitor.
	 * @param group the group to be cancelled.  It must match the currently running group or nothing
	 * will happen.
	 */
	public void cancelRunningGroup(GTaskGroup group) {
		lock.lock();
		try {
			if (group == runningGroup) {
				group.setCancelled();
				if (runningTask != null) {
					runningTask.getTaskMonitor().cancel();
				}
				if (suspended) {
					processCancelledJobsInPriorityQ();
				}
			}
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Cancels all scheduled groups and tasks. The TaskMonitor for
	 * the currently running task will be cancelled, but the task will continue to run until it
	 * checks the monitor.
	 */
	public void cancelAll() {
		lock.lock();
		try {
			if (runningGroup != null) {
				runningGroup.setCancelled();
				if (runningTask != null) {
					runningTask.getTaskMonitor().cancel();
				}
			}
			for (GTaskGroup group : taskGroupList) {
				group.setCancelled();
			}
			if (suspended) {
				processCancelledJobsInPriorityQ();
				processCancelledGroups();
			}
		}
		finally {
			lock.unlock();
		}

	}

	private synchronized void wakeUpWaitingThread() {
		notify();
	}

	private synchronized void doWait() {
		try {
			lock.unlock();
			wait();
			lock.lock();
		}
		catch (InterruptedException e) {
			// ignore
		}
	}

	private void runNextTaskIfNotBusyOrSuspended() {
		if (!suspended) {
			runNextTaskIfNotBusy();
		}
	}

	private void runNextTaskIfNotBusy() {
		if (runningTask != null) {
			return;
		}
		if (processNextTaskInPriorityQ()) {
			return;
		}

		processNextTaskGroup();

		processNextTaskInPriorityQ();
	}

	private void processNextTaskGroup() {
		if (runningGroup != null) {
			notifyGroupCompleted(runningGroup);
			runningGroup = null;
		}
		if (taskGroupList.isEmpty()) {
			closeTransaction();
			notBusy.signal();
			return;
		}

		GTaskGroup nextGroup = taskGroupList.removeFirst();
		prepareGroup(nextGroup);

	}

	private void prepareGroup(GTaskGroup taskGroup) {
		List<GScheduledTask> tasks = taskGroup.getTasks();
		priorityQ.addAll(tasks);
		if (taskGroup.wantsNewTransaction()) {
			closeTransaction();
		}
		openTransaction(taskGroup.getDescription());
		runningGroup = taskGroup;
		notifyGroupStarted(taskGroup);
	}

	private void openTransaction(String description) {
		if (currentGroupTransactionID == null) {
			currentGroupTransactionID = domainObject.startTransaction(description);
		}
	}

	private void closeTransaction() {
		if (currentGroupTransactionID != null) {
			domainObject.endTransaction(currentGroupTransactionID, true);
			currentGroupTransactionID = null;
		}
	}

	private boolean processNextTaskInPriorityQ() {
		if (priorityQ.isEmpty()) {
			return false;
		}
		runningTask = priorityQ.first();
		priorityQ.remove(runningTask);
		isBusy.signal();

		threadPool.submit(new GTaskRunnable(runningTask));
		return true;
	}

	private void taskCompleted(GScheduledTask task, Exception e) {
		lock.lock();
		try {
			GTaskResult result = new GTaskResult(runningGroup, task, e, currentGroupTransactionID);
			task.getGroup().taskCompleted();
			notifyTaskCompleted(task, result);
			results.add(result);
			if (results.size() > MAX_RESULTS) {
				results.remove();
			}
			runningTask = null;
			if (delayedTaskStack.isEmpty()) {
				runNextTaskIfNotBusyOrSuspended();
			}
		}
		finally {
			lock.unlock();
		}
	}

	private void notifyTaskStarted(GScheduledTask task) {
		if (taskListener == null) {
			return;
		}
		try {
			taskListener.taskStarted(task);
		}
		catch (Throwable unexpected) {
			Msg.error(this, "Unexpected exception notifying listener of task started", unexpected);
		}
	}

	private void notifyTaskCompleted(GScheduledTask task, GTaskResult result) {
		if (taskListener == null) {
			return;
		}
		try {
			taskListener.taskCompleted(task, result);
		}
		catch (Throwable unexpected) {
			Msg.error(this, "Unexpected exception notifying listener of task completed", unexpected);
		}
	}

	private void notifyTaskGroupScheduled(GTaskGroup group) {
		if (taskListener == null) {
			return;
		}
		try {
			taskListener.taskGroupScheduled(group);
		}
		catch (Throwable unexpected) {
			Msg.error(this, "Unexpected exception notifying listener of group scheduled",
				unexpected);
		}
	}

	private void notifyTaskScheduled(GScheduledTask scheduledTask) {
		if (taskListener == null) {
			return;
		}
		try {
			taskListener.taskScheduled(scheduledTask);
		}
		catch (Throwable unexpected) {
			Msg.error(this, "Unexpected exception notifying listener of task scheduled", unexpected);
		}
	}

	private void notifyGroupStarted(GTaskGroup taskGroup) {
		if (taskListener == null) {
			return;
		}
		try {
			taskListener.taskGroupStarted(taskGroup);
		}
		catch (Throwable unexpected) {
			Msg.error(this, "Unexpected exception notifying listener of group started", unexpected);
		}
	}

	private void notifyGroupCompleted(GTaskGroup taskGroup) {
		if (taskListener == null) {
			return;
		}
		try {
			taskListener.taskGroupCompleted(taskGroup);
		}
		catch (Throwable unexpected) {
			Msg.error(this, "Unexpected exception notifying listener of group completed",
				unexpected);
		}
	}

	private void notifySuspendedStateChanged() {
		if (taskListener == null) {
			return;
		}
		try {
			taskListener.suspendedStateChanged(suspended);
		}
		catch (Throwable unexpected) {
			Msg.error(this, "Unexpected exception notifying listener of suspended state changed",
				unexpected);
		}
	}

	private class GTaskRunnable implements Runnable {

		private GScheduledTask scheduledTask;

		GTaskRunnable(GScheduledTask task) {
			this.scheduledTask = task;
		}

		@Override
		public void run() {
			try {
				scheduledTask.setThread(Thread.currentThread());
				notifyTaskStarted(scheduledTask);

				if (scheduledTask.getGroup().wasCancelled()) {
					taskCompleted(scheduledTask, new CancelledException());
					return;
				}

				scheduledTask.getTask().run(domainObject, scheduledTask.getTaskMonitor());
				taskCompleted(scheduledTask, null);
			}
			catch (Exception e) {
				taskCompleted(scheduledTask, e);
			}
		}

	}

	private void processCancelledGroups() {
		for (GTaskGroup group : taskGroupList) {
			for (GScheduledTask task : group.getTasks()) {
				taskCompleted(task, new CancelledException());
			}
			notifyGroupCompleted(group);
		}
		taskGroupList.clear();
	}

	private void processCancelledJobsInPriorityQ() {
		for (GScheduledTask task : priorityQ) {
			taskCompleted(task, new CancelledException());
		}
		priorityQ.clear();
		if (runningGroup != null) {
			notifyGroupCompleted(runningGroup);
			runningGroup = null;
		}
	}

}
