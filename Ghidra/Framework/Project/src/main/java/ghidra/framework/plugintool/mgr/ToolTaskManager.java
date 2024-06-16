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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Function;

import javax.swing.JComponent;
import javax.swing.SwingUtilities;

import ghidra.framework.cmd.*;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectException;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.datastruct.PriorityQueue;
import ghidra.util.exception.RollbackException;
import ghidra.util.task.*;

/**
 * Manages a queue of background tasks that execute commands.
 */
public class ToolTaskManager implements Runnable {

	private static final String TIME_FORMAT_STRING = "yyyy-MM-dd HH:mm:ss";
	private static final DateTimeFormatter TIME_FORMATTER =
		DateTimeFormatter.ofPattern(TIME_FORMAT_STRING);

	private volatile PluginTool tool;
	private volatile boolean isExecuting;

	private LinkedList<BackgroundCommandTask<?>> tasks = new LinkedList<>();
	private Map<DomainObject, PriorityQueue<BackgroundCommand<?>>> queuedCommandsMap =
		new HashMap<>();
	private long startQueueTime = 0;
	private long startTaskTime = 0;
	private Thread taskThread;
	private ThreadGroup taskThreadGroup;
	private ToolTaskMonitor toolTaskMonitor;
	private BackgroundCommandTask<?> currentTask;
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
	 * Execute the given command in the foreground.  Required domain object transaction will be
	 * started with delayed end to ensure that any follow-on analysis starts prior to transaction 
	 * end.
	 * 
	 * @param <T> {@link DomainObject} implementation interface
	 * @param commandName command name to be associated with transaction
	 * @param domainObject domain object to be modified
	 * @param f command function callback which should return true on success or false on failure.
	 * @return result from command function callback
	 */
	public <T extends DomainObject> boolean execute(String commandName, T domainObject,
			Function<T, Boolean> f) {
		return execute(new SimpleCommand<T>(commandName, f), domainObject);
	}

	/**
	 * Execute the given command in the foreground.  Required domain object transaction will be
	 * started with delayed end to ensure that any follow-on analysis starts prior to transaction 
	 * end.
	 *
	 * @param cmd command to execute
	 * @param obj domain object to which the command will be applied
	 * @return the completion status of the command
	 *
	 * @see Command#applyTo(DomainObject)
	 */
	public <T extends DomainObject> boolean execute(Command<T> cmd, T obj) {
		if (tool == null) {
			return false; // disposed
		}

		tool.clearStatusInfo();
		boolean success = false;
		isExecuting = true;
		try {
			success = applyCommand(cmd, obj);
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

	private <T extends DomainObject> boolean applyCommand(Command<T> cmd, T domainObject) {

		boolean success = false;
		boolean error = false;
		String cmdName = cmd.getName();
		int txId = domainObject.startTransaction(cmdName);
		try {
			try {
				success = cmd.applyTo(domainObject);

				// Schedule empty background task to trigger flushEvents and processing of 
				// resulting queued commands.  This is standard behavior when any
				// BackgroundCommand completes its execution (see taskCompleted method).
				executeCommand(new EmptyBackgroundCommand<T>(cmdName), domainObject);
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
			domainObject.endTransaction(txId, !error);
		}

		return success;
	}

	/**
	 * Execute the given command in the background
	 *
	 * @param cmd background command
	 * @param obj domain object that supports undo/redo
	 */
	public synchronized <T extends DomainObject> void executeCommand(BackgroundCommand<T> cmd,
			T obj) {
		if (tool == null) {
			return;
		}

		BackgroundCommandTask<T> task = new BackgroundCommandTask<>(this, obj, cmd);
		tasks.addLast(task);

		if (taskThread != null && taskThread.isAlive()) {
			return;
		}

		taskThread = new Thread(taskThreadGroup, this, "Background-Task-" + tool.getName());
		taskThread.setPriority(Thread.MIN_PRIORITY + 1);
		taskThread.start();
		try {
			// Wait for background command task to start its transaction and notify us.
			// This is done to ensure any preceeding foreground Command transaction
			// becomes entangled with the task execution.
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
	public synchronized <T extends DomainObject> void scheduleFollowOnCommand(
			BackgroundCommand<T> cmd, T obj) {

		if (isProcessingDomainObject(obj)) {

			PriorityQueue<BackgroundCommand<?>> queue = queuedCommandsMap.get(obj);
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

	private boolean isProcessingDomainObject(DomainObject obj) {
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

	private <T extends DomainObject> boolean mergeMergeableBackgroundCommands(
			BackgroundCommand<T> newCommand, PriorityQueue<BackgroundCommand<?>> queue) {
		@SuppressWarnings("unchecked")
		BackgroundCommand<T> lastCommand = (BackgroundCommand<T>) queue.getLast();
		if (!(lastCommand instanceof MergeableBackgroundCommand) ||
			!(newCommand instanceof MergeableBackgroundCommand)) {
			return false;
		}

		// merge the two into the original command, as it is still in the queue in the correct
		// place
		MergeableBackgroundCommand<T> mergeableBackgroundCommand =
			(MergeableBackgroundCommand<T>) lastCommand;
		MergeableBackgroundCommand<T> newMergeableBackgroundCommand =
			(MergeableBackgroundCommand<T>) newCommand;
		mergeableBackgroundCommand.mergeCommands(newMergeableBackgroundCommand);
		return true;
	}

	/**
	 * Cancel the currently running task and clear all commands that are scheduled to run. Block
	 * until the currently running task ends.
	 *
	 * @param monitor a monitor to cancel waiting for the task to finish
	 */
	public void stop(TaskMonitor monitor) {

		synchronized (this) {
			if (isBusy()) {
				toolTaskMonitor.cancel();
			}
			if (currentTask != null) {
				clearQueuedCommands(currentTask.getDomainObject());
			}
		}

		while (taskThread != null && !monitor.isCancelled()) {
			try {
				Thread.sleep(100);
			}
			catch (InterruptedException e) {
				// try again
			}
		}
	}

	private String time() {
		if (!SystemUtilities.isInDevelopmentMode()) {
			// The dev console log appender does not show date info for log messages.  This method
			// allows us to show the time in the dev console, which is useful for debugging.  The
			// application log files always contain a date for each message.
			return "";
		}

		LocalDateTime localDate = DateUtils.toLocalDate(new Date());
		return TIME_FORMATTER.format(localDate) + " ";
	}

	@Override
	public void run() {
		try {

			Msg.debug(this, time() + "Background processing started...");
			startQueueTime = System.currentTimeMillis();
			for (BackgroundCommandTask<?> task = getNextTask(); task != null; task =
				getNextTask()) {

				Msg.debug(this, time() + "Task Start: " + task.getTaskTitle());
				startTaskTime = System.currentTimeMillis();

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

			double totalTime = (System.currentTimeMillis() - startQueueTime) / 1000.00;
			Msg.debug(this, time() + "Background processing complete (" + totalTime + " secs)");
		}
		finally {
			synchronized (this) {
				currentTask = null;
			}
		}
	}

	private synchronized BackgroundCommandTask<?> getNextTask() {
		if (tasks.isEmpty()) {
			taskThread = null;
			return null;
		}
		return tasks.removeFirst();
	}

	private synchronized <T extends DomainObject> BackgroundCommand<T> getNextCommand(T obj) {
		PriorityQueue<BackgroundCommand<?>> queue = queuedCommandsMap.get(obj);
		if (queue == null) {
			return null;
		}
		@SuppressWarnings("unchecked")
		BackgroundCommand<T> cmd = (BackgroundCommand<T>) queue.removeFirst();
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
	public <T extends DomainObject> void taskCompleted(T obj, BackgroundCommandTask<T> task,
			TaskMonitor monitor) {

		obj.flushEvents();

		try {
			while (!monitor.isCancelled()) {
				BackgroundCommand<T> cmd;
				synchronized (this) {
					cmd = getNextCommand(obj);
					if (cmd == null) {
						// any late follow-on commands will require a new task
						task.setDoneQueueProcessing();
						break;
					}
				}
				Msg.debug(this, time() + "Start: " + cmd.getName());
				toolTaskMonitor.updateTaskCmd(cmd);
				long localStart = System.currentTimeMillis();
				cmd.applyTo(obj, monitor);
				cmd.taskCompleted();
				double totalTime = (System.currentTimeMillis() - localStart) / 1000.00;
				Msg.debug(this,
					time() + "Completed: " + cmd.getName() + " (" + totalTime + " secs)");
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
		double totalTime = (System.currentTimeMillis() - startTaskTime) / 1000.00;
		Msg.debug(this,
			time() + "Task Completed: " + task.getTaskTitle() + " (" + totalTime + " secs)");
	}

	/**
	 * Clear the queue of scheduled commands.
	 * @param obj domain object
	 */
	public synchronized void clearQueuedCommands(DomainObject obj) {
		PriorityQueue<BackgroundCommand<?>> queue = queuedCommandsMap.get(obj);
		if (queue == null) {
			return;
		}
		while (!queue.isEmpty()) {
			BackgroundCommand<?> cmd = queue.removeFirst();
			cmd.dispose();
		}
		queuedCommandsMap.remove(obj);
	}

	/**
	 * Clear all tasks associated with specified domain object.
	 *
	 * @param obj domain object
	 */
	public synchronized void clearTasks(DomainObject obj) {
		Iterator<BackgroundCommandTask<?>> iter = tasks.iterator();
		while (iter.hasNext()) {
			BackgroundCommandTask<?> task = iter.next();
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
	public <T extends DomainObject> void taskFailed(T obj, BackgroundCommand<T> taskCmd,
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

	/**
	 * Clear list of tasks and queue of scheduled commands.
	 */
	public synchronized void dispose() {

		clearTasks();
		List<DomainObject> list = new ArrayList<>(queuedCommandsMap.keySet());
		for (DomainObject obj : list) {
			clearQueuedCommands(obj);
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
		for (BackgroundCommandTask<?> task : tasks) {
			if (task.getDomainObject() == domainObject) {
				return true;
			}
		}
		return false;
	}

	private static class EmptyBackgroundCommand<T extends DomainObject>
			extends BackgroundCommand<T> {

		public EmptyBackgroundCommand(String name) {
			super(name, false, true, false);
		}

		@Override
		public boolean applyTo(T obj, TaskMonitor monitor) {
			return true;
		}
	}

	/**
	 * {@link SimpleCommand} provides a convenience command for wrapping a lambda function
	 * into a foreground {@link Command} for execution by the task manager.
	 *
	 * @param <T> {@link DomainObject} implementation class
	 */
	private static class SimpleCommand<T extends DomainObject> implements Command<T> {

		private String commandName;
		private Function<T, Boolean> f;

		SimpleCommand(String commandName, Function<T, Boolean> f) {
			this.commandName = commandName;
			this.f = f;
		}

		@Override
		public boolean applyTo(T domainObject) {
			return f.apply(domainObject);
		}

		@Override
		public String getStatusMsg() {
			return null;
		}

		@Override
		public String getName() {
			return commandName;
		}
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

	public void updateTaskCmd(BackgroundCommand<?> cmd) {
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
