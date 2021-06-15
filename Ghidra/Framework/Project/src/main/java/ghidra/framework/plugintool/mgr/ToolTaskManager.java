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
package ghidra.framework.plugintool.mgr;

import java.awt.Dimension;
import java.rmi.ConnectException;
import java.util.*;

import javax.swing.JComponent;
import javax.swing.SwingUtilities;

import ghidra.framework.cmd.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.datastruct.PriorityQueue;
import ghidra.util.exception.RollbackException;
import ghidra.util.task.*;

/**
 * Manages a queue of background tasks that execute commands.
 */
public class ToolTaskManager implements Runnable {
	private volatile PluginTool tool;
	private volatile boolean isExecuting;

	private LinkedList<BackgroundCommandTask> tasks = new LinkedList<>();
	private Map<UndoableDomainObject, PriorityQueue<BackgroundCommand>> queuedCommandsMap =
		new HashMap<>();
	private Map<UndoableDomainObject, Integer> openForgroundTransactionIDs = new HashMap<>();
	private long start_time = 0;
	private Thread taskThread;
	private ThreadGroup taskThreadGroup;
	private ToolTaskMonitor toolTaskMonitor;
	private BackgroundCommandTask currentTask;
	private TaskDialog modalTaskDialog;

	/**
	 * Construct a new ToolTaskManager.
	 *
	 * @param tool tool associated with this ToolTaskManager
	 */
	public ToolTaskManager(PluginTool tool) {
		this.tool = tool;
		toolTaskMonitor = new ToolTaskMonitor(tool);
		toolTaskMonitor.setName("Progress Monitor");
		taskThreadGroup = new ThreadGroup(Thread.currentThread().getThreadGroup(),
			"Background-Task-Group-" + tool.getName());
	}

	/**
	 * Returns the thread group associated with all background tasks run by this
	 * manager and their instantiated threads.
	 *
	 * @return task thread group
	 */
	public ThreadGroup getTaskThreadGroup() {
		return taskThreadGroup;
	}

	/**
	 * Get the monitor component that shows progress and has a cancel button.
	 *
	 * @return the monitor component
	 */
	public JComponent getMonitorComponent() {
		return toolTaskMonitor;
	}

	/**
	 * Return true if a task is executing
	 *
	 * @return true if a task is executing
	 */
	public synchronized boolean isBusy() {
		return isExecuting || (taskThread != null && taskThread.isAlive());
	}

	/**
	 * Execute the given command in the foreground
	 *
	 * @param cmd command to execute
	 * @param obj domain object to which the command will be applied
	 * @return the completion status of the command
	 *
	 * @see Command#applyTo(DomainObject)
	 */
	public boolean execute(Command cmd, DomainObject obj) {
		if (tool == null) {
			return false; // disposed
		}

		tool.clearStatusInfo();
		boolean success = false;
		isExecuting = true;
		try {
			if (obj instanceof UndoableDomainObject) {
				UndoableDomainObject undoObj = (UndoableDomainObject) obj;
				success = applyCommand(cmd, undoObj);
			}
			else {
				success = cmd.applyTo(obj);
			}
		}
		finally {
			isExecuting = false;
		}

		if (!success) {
			String statusMessage = cmd.getName() + " failed";
			String cmdMessage = cmd.getStatusMsg();
			if (cmdMessage != null) {
				statusMessage += ": " + cmdMessage;
			}
			tool.setStatusInfo(statusMessage);
		}

		return success;
	}

	private boolean applyCommand(Command cmd, UndoableDomainObject domainObject) {

		boolean success = false;
		boolean error = false;
		String cmdName = cmd.getName();
		int id = domainObject.startTransaction(cmdName);
		try {
			try {
				success = cmd.applyTo(domainObject);

				// TODO Ok, this seems bad--why track the success of the given command, but
				// not any of the queued commands?  (Are they considered unrelated follow-up
				// commands?)
				executeQueueCommands(domainObject, cmdName);
			}
			catch (Throwable t) {
				error = true;
				clearQueuedCommands(domainObject);
				if (t instanceof DomainObjectException) {
					t = t.getCause();
				}

				// these are not 'unexpected', so don't show the user
				if (t instanceof ConnectException) {
					return false;
				}
				if (t instanceof RollbackException) {
					return false;
				}

				Msg.showError(this, null, "Command Failure",
					"An unexpected error occurred running command: " + cmd.getName(), t);
			}
		}
		finally {
			domainObject.endTransaction(id, !error);
		}

		return success;
	}

	/**
	 * Execute the given command in the background
	 *
	 * @param cmd background command
	 * @param obj domain object that supports undo/redo
	 */
	public synchronized void executeCommand(BackgroundCommand cmd, UndoableDomainObject obj) {
		if (tool == null) {
			return;
		}

		BackgroundCommandTask task = new BackgroundCommandTask(this, obj, cmd);
		tasks.addLast(task);
		start_time = System.currentTimeMillis();
		if (taskThread != null && taskThread.isAlive()) {
			return;
		}

		taskThread = new Thread(taskThreadGroup, this, "Background-Task-" + tool.getName());
		taskThread.setPriority(Thread.MIN_PRIORITY + 1);
		taskThread.start();
		try {
			// We will get notified by the task, after it has started the transaction

			// TODO: why do we need to wait until the transaction is started?!?
			wait(1000);
		}
		catch (InterruptedException e) {
			Msg.error(this,
				"Interrupted waiting for the Background Command to start a transaction");
		}
	}

	/**
	 * Schedule the given background command when the current command completes.
	 *
	 * @param cmd background command to be scheduled
	 * @param obj domain object that supports undo/redo
	 */
	public synchronized void scheduleFollowOnCommand(BackgroundCommand cmd,
			UndoableDomainObject obj) {
		if (isProcessingDomainObject(obj)) {

			PriorityQueue<BackgroundCommand> queue = queuedCommandsMap.get(obj);
			if (queue == null) {
				queue = new PriorityQueue<>();
				queuedCommandsMap.put(obj, queue);
			}

			// no need to add repeated entries to the queue
			if (!mergeMergeableBackgroundCommands(cmd, queue)) {
				queue.add(cmd, 1);
			}
		}
		else {
			executeCommand(cmd, obj);
		}
	}

	private boolean isProcessingDomainObject(UndoableDomainObject obj) {
		if (taskThread == null) {
			return false;
		}
		if (hasQueuedTasksForDomainObject(obj)) {
			// any queued task will process queued follow-on commands
			return true;
		}
		// NOTE: while current task may not have completed (not null) it may be
		// done processing queued commands
		return currentTask != null && !currentTask.isDoneQueueProcessing();
	}

	private boolean mergeMergeableBackgroundCommands(BackgroundCommand newCommand,
			PriorityQueue<BackgroundCommand> queue) {
		BackgroundCommand lastCommand = queue.getLast();
		if (!(lastCommand instanceof MergeableBackgroundCommand) ||
			!(newCommand instanceof MergeableBackgroundCommand)) {
			return false;
		}

		// merge the two into the original command, as it is still in the queue in the correct
		// place
		MergeableBackgroundCommand mergeableBackgroundCommand =
			(MergeableBackgroundCommand) lastCommand;
		MergeableBackgroundCommand newMergeableBackgroundCommand =
			(MergeableBackgroundCommand) newCommand;
		mergeableBackgroundCommand.mergeCommands(newMergeableBackgroundCommand);
		return true;
	}

	/**
	 * Cancel the currently running task and clear all commands that are
	 * scheduled to run. Block until the currently running task ends.
	 *
	 * @param wait if true wait for current task to cancel cleanly
	 */
	public void stop(boolean wait) {

		Thread oldTaskThread = null;
		synchronized (this) {
			if (isBusy()) {
				toolTaskMonitor.cancel();
				oldTaskThread = taskThread;
			}
			if (currentTask != null) {
				clearQueuedCommands(currentTask.getDomainObject());
			}
		}

		if (oldTaskThread != null && wait) {
			try {
				oldTaskThread.join();
			}
			catch (InterruptedException e) {
				// guess we don't care?
			}
		}
	}

	/**
	 * @see java.lang.Runnable#run()
	 */
	@Override
	public void run() {
		try {
			for (BackgroundCommandTask task = getNextTask(); task != null; task = getNextTask()) {

				Msg.debug(this, "Exec Task " + task.getTaskTitle());

				synchronized (this) {
					currentTask = task;
				}

				if (task.isModal()) {
					modalTaskDialog = new TaskDialog(task);
					modalTaskDialog.show(0);
					task.run(modalTaskDialog);
				}
				else {
					toolTaskMonitor.initialize(task);
					task.run(toolTaskMonitor);
				}
			}
		}
		finally {
			synchronized (this) {
				currentTask = null;
			}
		}
	}

	private synchronized BackgroundCommandTask getNextTask() {
		if (tasks.isEmpty()) {
			taskThread = null;
			return null;
		}
		return tasks.removeFirst();
	}

	private synchronized BackgroundCommand getNextCommand(UndoableDomainObject obj) {
		PriorityQueue<BackgroundCommand> queue = queuedCommandsMap.get(obj);
		if (queue == null) {
			return null;
		}
		BackgroundCommand cmd = queue.removeFirst();
		if (queue.isEmpty()) {
			queuedCommandsMap.remove(obj);
		}
		return cmd;
	}

	/**
	 * Notification from the BackgroundCommandTask that it has completed; queued
	 * or scheduled commands are executed.
	 *
	 * @param obj domain object that supports undo/redo
	 * @param task background command task that has completed
	 * @param monitor task monitor
	 */
	public void taskCompleted(UndoableDomainObject obj, BackgroundCommandTask task,
			TaskMonitor monitor) {
		double taskTime = (System.currentTimeMillis() - start_time) / 1000.00;
		Msg.debug(this, "  task finish (" + taskTime + " secs)");
		obj.flushEvents();
		try {
			while (!monitor.isCancelled()) {
				BackgroundCommand cmd;
				synchronized (this) {
					cmd = getNextCommand(obj);
					if (cmd == null) {
						// any late follow-on commands will require a new task
						task.setDoneQueueProcessing();
						break;
					}
				}
				Msg.debug(this, "    Queue - " + cmd.getName());
				toolTaskMonitor.updateTaskCmd(cmd);
				long localStart = System.currentTimeMillis();
				cmd.applyTo(obj, monitor);
				cmd.taskCompleted();
				double totalTime = (System.currentTimeMillis() - localStart) / 1000.00;
				Msg.debug(this, "   (" + totalTime + " secs)");
				obj.flushEvents();
			}
		}
		finally {
			try {
				if (monitor.isCancelled()) {
					clearQueuedCommands(obj);
					if (tool != null) {
						tool.setStatusInfo(task.getCommand().getName() + " cancelled");
					}
				}
				synchronized (this) {
					Integer openForgroundTransactionID = openForgroundTransactionIDs.remove(obj);
					if (openForgroundTransactionID != null) {
						obj.endTransaction(openForgroundTransactionID, true);
					}
				}
			}
			finally {
				if (currentTask.isModal()) {
					modalTaskDialog.taskProcessed();
					modalTaskDialog = null;
				}
				else {
					toolTaskMonitor.taskCompleted(currentTask);
				}
			}
		}
		task.getCommand().taskCompleted();
		double totalTime = (System.currentTimeMillis() - start_time) / 1000.00;
		Msg.debug(this, "  task complete (" + totalTime + " secs)");
	}

	/**
	 * Clear the queue of scheduled commands.
	 */
	public synchronized void clearQueuedCommands(UndoableDomainObject obj) {
		PriorityQueue<BackgroundCommand> queue = queuedCommandsMap.get(obj);
		if (queue == null) {
			return;
		}
		while (!queue.isEmpty()) {
			BackgroundCommand cmd = queue.removeFirst();
			cmd.dispose();
		}
		queuedCommandsMap.remove(obj);
	}

	/**
	 * Clear all tasks associated with specified domain object.
	 *
	 * @param obj domain object
	 */
	public synchronized void clearTasks(UndoableDomainObject obj) {
		Iterator<BackgroundCommandTask> iter = tasks.iterator();
		while (iter.hasNext()) {
			BackgroundCommandTask task = iter.next();
			if (task.getDomainObject() == obj) {
				iter.remove();
			}
		}
	}

	/**
	 * Notification from the BackgroundCommandTask that the given command
	 * failed. Any scheduled commands are cleared from the queue.
	 *
	 * @param obj domain object that supports undo/redo
	 * @param taskCmd background command that failed
	 * @param monitor task monitor for the background task
	 */
	public void taskFailed(UndoableDomainObject obj, BackgroundCommand taskCmd,
			TaskMonitor monitor) {
		try {
			obj.flushEvents();
			clearQueuedCommands(obj);
			if (tool != null) {
				if (!monitor.isCancelled()) {
					monitor.cancel();
					String msg = taskCmd.getStatusMsg();
					if (msg == null || msg.length() == 0) {
						msg = "Unspecified error occurred.";
					}
					Msg.showError(this, tool.getToolFrame(), taskCmd.getName() + " Failed", msg);
				}
				else {
					tool.setStatusInfo(taskCmd.getName() + " cancelled");
				}
			}
		}
		finally {
			if (currentTask.isModal()) {
				modalTaskDialog.taskProcessed();
				modalTaskDialog = null;
			}
			else {
				toolTaskMonitor.taskCompleted(currentTask);
			}
		}
	}

	private void executeQueueCommands(UndoableDomainObject obj, String title) {
		obj.flushEvents();
		synchronized (this) {
			PriorityQueue<BackgroundCommand> queue = queuedCommandsMap.get(obj);
			if (queue == null) {
				return; // nothing is queued
			}
			if (!openForgroundTransactionIDs.containsKey(obj)) {
				// persist transaction to include follow-on changes
				openForgroundTransactionIDs.put(obj, obj.startTransaction(title));
			}
		}
		// schedule task to process command queue
		BackgroundCommand cmd = new EmptyBackgroundCommand();
		executeCommand(cmd, obj);
	}

	/**
	 * Clear list of tasks and queue of scheduled commands.
	 */
	public synchronized void dispose() {
		clearTasks();
		List<UndoableDomainObject> list = new ArrayList<>(queuedCommandsMap.keySet());
		for (UndoableDomainObject obj : list) {
			clearQueuedCommands(obj);
			Integer txId = openForgroundTransactionIDs.get(obj);
			if (txId != null) {
				obj.endTransaction(txId, true);
			}
		}
		queuedCommandsMap = new HashMap<>();

		toolTaskMonitor.dispose();
		if (modalTaskDialog != null) {
			modalTaskDialog.dispose();
		}

		tool = null;
	}

	/**
	 * Clear the list of tasks.
	 */
	public synchronized void clearTasks() {
		tasks.clear();
	}

	/**
	 * Cancel the current task.
	 */
	public void cancelCurrentTask() {
		toolTaskMonitor.cancel();
	}

	public synchronized boolean hasTasksForDomainObject(DomainObject domainObject) {
		if (!isBusy()) {
			return false;
		}
		if (currentTask != null) {
			if (currentTask.getDomainObject() == domainObject) {
				return true;
			}
		}
		return hasQueuedTasksForDomainObject(domainObject);
	}

	private synchronized boolean hasQueuedTasksForDomainObject(DomainObject domainObject) {
		Iterator<BackgroundCommandTask> iter = tasks.iterator();
		while (iter.hasNext()) {
			BackgroundCommandTask task = iter.next();
			if (task.getDomainObject() == domainObject) {
				return true;
			}
		}
		return false;
	}

}

class EmptyBackgroundCommand extends BackgroundCommand {

	public EmptyBackgroundCommand() {
		super("Empty Background Command", false, true, false);
	}

	/**
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject,
	 *      ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		return true;
	}
}

class ToolTaskMonitor extends TaskMonitorComponent implements TaskListener {
	private PluginTool tool;
	private Runnable addPanelRunnable;
	private Runnable removePanelRunnable;

	ToolTaskMonitor(PluginTool pluginTool) {
		this.tool = pluginTool;
		addPanelRunnable = () -> {
			if (tool != null) {
				tool.addStatusComponent(ToolTaskMonitor.this, false, true);
			}
		};
		removePanelRunnable = () -> {
			if (tool != null) {
				tool.removeStatusComponent(ToolTaskMonitor.this);
			}
		};
	}

	public void updateTaskCmd(BackgroundCommand cmd) {
		showProgress(cmd.hasProgress());
		setTaskName(cmd.getName());
	}

	void initialize(Task task) {
		if (tool == null) {
			return; // disposed
		}

		reset();
		showProgress(task.hasProgress());
		task.addTaskListener(this);
		setTaskName(task.getTaskTitle());
		setCancelEnabled(task.canCancel());
		SwingUtilities.invokeLater(addPanelRunnable);
	}

	void dispose() {
		cancel();
		tool = null;
	}

	@Override
	public void taskCompleted(Task task) {
		SwingUtilities.invokeLater(removePanelRunnable);
	}

	@Override
	public void taskCancelled(Task task) {
		SwingUtilities.invokeLater(removePanelRunnable);
	}

	@Override
	public Dimension getPreferredSize() {
		Dimension preferredSize = super.getPreferredSize();

		// Somewhat arbitrary value, but the default is too small to read most messages. So,
		// give some extra width, but not so much as to too badly push off the status area of
		// the tool window.  This value is based upon some of the longer messages that we use.
		preferredSize.width += 200;
		return preferredSize;
	}
}
