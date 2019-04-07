/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.task.gui.taskview;

import ghidra.framework.task.*;
import ghidra.framework.task.gui.GProgressBar;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.SwingUpdateManager;

import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.swing.*;

import org.jdesktop.animation.timing.*;

import docking.util.GraphicsUtils;

/*
 * The TaskViewer manages a component for showing the running and waiting tasks of a GTaskManager.
 */
public class TaskViewer {
	private final Composite SCROLLED_TEXT_ALPHA_COMPOSITE = AlphaComposite.getInstance(
		AlphaComposite.SrcOver.getRule(), .10f);
	private static final String TEXT = "PAUSED...";
	private static final int MIN_DELAY = 250;
	private static final int MAX_DELAY = 1000;

	private Deque<AbstractTaskInfo> runningList = new LinkedList<AbstractTaskInfo>();
	private LinkedList<AbstractTaskInfo> waitingList = new LinkedList<AbstractTaskInfo>();
	private LinkedList<AbstractTaskInfo> scrollAwayList = new LinkedList<AbstractTaskInfo>();
	private Queue<Runnable> runnableQueue = new ConcurrentLinkedQueue<Runnable>();
	private SwingUpdateManager updateManager;
	private GTaskManager taskManager;
	private TaskViewerTaskListener taskListener;

	/**
	 * Uses a layered pane to create a "watermark effect" to show when the GTaskManger is suspended.
	 */
	private JLayeredPane layeredPane;
	private TaskViewerComponent taskViewerComponent;

	private boolean useAnimations = true;
	private Animator scrollAwayAnimator;
	private TimingTarget completedTimingTarget;
	private Runnable animationRunnable;
	private Runnable updateComponentsRunnable;

	public TaskViewer(GTaskManager taskManager) {
		this.taskManager = taskManager;

		buildComponent();
		taskListener = new TaskViewerTaskListener();
		updateComponentsRunnable = new Runnable() {
			@Override
			public void run() {
				while (!runnableQueue.isEmpty()) {
					Runnable runnable = runnableQueue.poll();
					runnable.run();
				}
				updateComponent();
			}
		};
		updateManager = new SwingUpdateManager(MIN_DELAY, MAX_DELAY, updateComponentsRunnable);
		animationRunnable = new Runnable() {

			@Override
			public void run() {
				startScrollingAwayAnimation(0);
			}
		};

		completedTimingTarget = new TimingTargetAdapter() {
			@Override
			public void timingEvent(float fraction) {
				scrollAwayList.getFirst().setScrollFraction(fraction);
				taskViewerComponent.getParent().validate();
				int desiredDuration = getDesiredDuration();
				if (scrollAwayAnimator.getDuration() != desiredDuration) {
					scrollAwayAnimator.cancel();
					scrollAwayAnimator.setDuration(desiredDuration);
					scrollAwayAnimator.setStartFraction(fraction);
					scrollAwayAnimator.start();
				}
			}

			@Override
			public void end() {
				AbstractTaskInfo element = scrollAwayList.pop();
				runningList.remove(element);
				updateComponent();
				SwingUtilities.invokeLater(animationRunnable);
			}
		};
		scrollAwayAnimator = new Animator(3000, completedTimingTarget);
		scrollAwayAnimator.setStartDelay(2000);

		// the listener must be added after everything is ready to go
		taskManager.addTaskListener(taskListener);
	}

	public void setUseAnimations(boolean b) {
		useAnimations = b;
	}

	private void buildComponent() {
		taskViewerComponent = new TaskViewerComponent();
		layeredPane = new JLayeredPane();
		layeredPane.setLayout(new CustomLayoutManager());
		JScrollPane scroll = new JScrollPane(taskViewerComponent);
		layeredPane.add(scroll, JLayeredPane.DEFAULT_LAYER);
		layeredPane.add(new MessageCanvas(), JLayeredPane.PALETTE_LAYER);
	}

	// determines the animation scrolling speed depending on how many items need to "scroll away".
	// The more items to scroll away, the faster the animation.
	private int getDesiredDuration() {
		int size = scrollAwayList.size();
		if (size < 4) {
			return 3000;
		}
		if (size < 6) {
			return 2000;
		}
		if (size < 8) {
			return 1000;
		}
		if (size < 10) {
			return 500;
		}
		if (size < 15) {
			return 250;
		}
		return 100;
	}

	private void updateComponent() {
		if (!SystemUtilities.isEventDispatchThread()) {
			throw new AssertException("Must be in swing thread");
		}
		taskViewerComponent.removeAll();
		for (AbstractTaskInfo element : runningList) {
			taskViewerComponent.add(element.getComponent());
		}

		if (waitingList.size() > 0 && runningList.size() > 0) {
			taskViewerComponent.add(new JSeparator());
		}

		for (AbstractTaskInfo element : waitingList) {
			taskViewerComponent.add(element.getComponent());
		}

		Container parent = taskViewerComponent.getParent();
		if (parent != null) {
			parent.validate();
		}
	}

	private void initializeRunningElement(TaskInfo taskInfo) {
		GProgressBar bar = taskInfo.setRunning();
		GTaskMonitor taskMonitor = taskInfo.getScheduledTask().getTaskMonitor();
		taskMonitor.setProgressBar(bar);
		if (taskInfo.getGroup().wasCancelled()) {
			bar.initialize(1);
			bar.setMessage("CANCELLED!");
		}
		runningList.add(taskInfo);
	}

	public JComponent getComponent() {
		return layeredPane;
	}

	void startScrollingAwayAnimation(int startDelay) {
		if (scrollAwayList.isEmpty()) {
			return;
		}
		if (scrollAwayAnimator.isRunning()) {
			return;
		}

		scrollAwayAnimator.setStartFraction(0f);
		scrollAwayAnimator.setDuration(getDesiredDuration());
		scrollAwayAnimator.setStartDelay(startDelay);
		scrollAwayAnimator.start();

	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	// this layout makes sure the main component and the layered pane are both sized together.  This
	// ensures the "watermark" message is centered.
	private class CustomLayoutManager implements LayoutManager {

		@Override
		public void addLayoutComponent(String name, Component comp) {
			// do nothing
		}

		@Override
		public void removeLayoutComponent(Component comp) {
			// do nothing
		}

		@Override
		public Dimension preferredLayoutSize(Container parent) {
			Insets insets = parent.getInsets();
			Dimension d = new Dimension();
			for (Component comp : parent.getComponents()) {
				Dimension size = comp.getPreferredSize();
				d.width = Math.max(d.width, size.width);
				d.height = Math.max(d.height, size.height);
			}
			d.width += insets.left + insets.right;
			d.height += insets.top + insets.bottom;
			return d;
		}

		@Override
		public Dimension minimumLayoutSize(Container parent) {
			return preferredLayoutSize(parent);
		}

		@Override
		public void layoutContainer(Container parent) {
			Dimension size = parent.getSize();
			Insets insets = parent.getInsets();
			int width = size.width - insets.left - insets.right;
			int height = size.height - insets.top - insets.bottom;
			int x = insets.left;
			int y = insets.top;
			for (Component comp : parent.getComponents()) {
				comp.setBounds(x, y, width, height);
			}
		}
	}

	private class MessageCanvas extends JComponent {
		private Rectangle messageDimension;

		@Override
		protected void paintComponent(Graphics g) {
			if (!taskManager.isSuspended()) {
				return;
			}
			Graphics2D g2 = (Graphics2D) g;
			g2.setComposite(SCROLLED_TEXT_ALPHA_COMPOSITE);

			Font font = new Font("Sanf Serif", Font.BOLD, 36);
			g.setFont(font);
			g.setColor(new Color(0, 0, 200));
			if (messageDimension == null) {
				FontMetrics fontMetrics = getFontMetrics(font);
				messageDimension = fontMetrics.getStringBounds(TEXT, g2).getBounds();
			}
			Dimension size = getSize();
			int centerY = size.height / 2;
			int centerX = size.width / 2;

			int x = centerX - messageDimension.width / 2;
			int y = centerY + messageDimension.height / 2;
			GraphicsUtils.drawString(this, g, TEXT, x, y);
		}
	}

	private class TaskViewerTaskListener extends GTaskListenerAdapter {

		@Override
		public void initialize() {
			runnableQueue.add(new InitializeRunnable());
			updateManager.updateNow();
		}

		@Override
		public void taskStarted(GScheduledTask task) {
			runnableQueue.add(new TaskStartedRunnable(task));
			updateManager.update();
		}

		@Override
		public void taskCompleted(GScheduledTask task, GTaskResult result) {
			runnableQueue.add(new TaskCompletedRunnable(task));
			updateManager.update();
		}

		@Override
		public void taskGroupScheduled(GTaskGroup group) {
			runnableQueue.add(new TaskGroupScheduledRunnable(group));
			updateManager.update();
		}

		@Override
		public void taskScheduled(GScheduledTask scheduledTask) {
			runnableQueue.add(new TaskScheduledRunnable(scheduledTask));
			updateManager.update();
		}

		@Override
		public void taskGroupStarted(GTaskGroup taskGroup) {
			runnableQueue.add(new TaskGroupStartedRunnable(taskGroup));
			updateManager.update();
		}

		@Override
		public void taskGroupCompleted(GTaskGroup taskGroup) {
			runnableQueue.add(new TaskGroupCompletedRunnable(taskGroup));
			updateManager.update();
		}

		@Override
		public void suspendedStateChanged(boolean isSuspended) {
			SystemUtilities.runSwingLater(new Runnable() {
				@Override
				public void run() {
					layeredPane.invalidate();
					layeredPane.repaint();
				}
			});
		}
	}

	private class InitializeRunnable implements Runnable {
		private GTaskGroup currentGroup;
		private List<GScheduledTask> scheduledTasks = new ArrayList<GScheduledTask>();
		private List<GScheduledTask> delayedTasks;
		private GScheduledTask runningTask;
		private List<TaskGroupScheduledRunnable> groupRunnables;

		public InitializeRunnable() {
			currentGroup = taskManager.getCurrentGroup();
			delayedTasks = taskManager.getDelayedTasks();
			scheduledTasks = taskManager.getScheduledTasks();
			runningTask = taskManager.getRunningTask();
			List<GTaskGroup> groups = taskManager.getScheduledGroups();

			groupRunnables = new ArrayList<TaskGroupScheduledRunnable>();
			for (GTaskGroup gTaskGroup : groups) {
				groupRunnables.add(new TaskGroupScheduledRunnable(gTaskGroup));
			}
		}

		@Override
		public void run() {
			waitingList.clear();
			if (currentGroup != null) {
				runningList.add(new GroupInfo(currentGroup));
				for (GScheduledTask gScheduledTask : delayedTasks) {
					initializeRunningElement(new TaskInfo(gScheduledTask));
				}
				if (runningTask != null) {
					initializeRunningElement(new TaskInfo(runningTask));
				}
				for (GScheduledTask gScheduledTask : scheduledTasks) {
					waitingList.add(new TaskInfo(gScheduledTask));
				}
			}
			for (TaskGroupScheduledRunnable runnable : groupRunnables) {
				runnable.run();
			}
			Collections.sort(waitingList);
			updateComponent();
		}
	}

	private class TaskStartedRunnable implements Runnable {
		private GScheduledTask task;

		TaskStartedRunnable(GScheduledTask task) {
			this.task = task;
		}

		@Override
		public void run() {
			Iterator<AbstractTaskInfo> it = waitingList.iterator();
			while (it.hasNext()) {
				AbstractTaskInfo info = it.next();
				if (!(info instanceof TaskInfo)) {
					continue;
				}
				TaskInfo taskInfo = (TaskInfo) info;
				if (taskInfo.getScheduledTask() == task) {
					it.remove();
					initializeRunningElement(taskInfo);
				}
			}
		}

	}

	private class TaskCompletedRunnable implements Runnable {
		private final GScheduledTask scheduledTask;

		public TaskCompletedRunnable(GScheduledTask task) {
			this.scheduledTask = task;
		}

		@Override
		public void run() {
			Iterator<AbstractTaskInfo> it = runningList.iterator();

			while (it.hasNext()) {
				AbstractTaskInfo info = it.next();
				if (!(info instanceof TaskInfo)) {
					continue;
				}
				GScheduledTask task = ((TaskInfo) info).getScheduledTask();
				if (task == scheduledTask) {
					if (useAnimations) {
						scrollAwayList.add(info);
						startScrollingAwayAnimation(2000);
					}
					else {
						it.remove();
					}
					return;
				}
			}

			it = waitingList.iterator();
			while (it.hasNext()) {
				AbstractTaskInfo info = it.next();
				if (!(info instanceof TaskInfo)) {
					continue;
				}
				GScheduledTask task = ((TaskInfo) info).getScheduledTask();
				if (task == scheduledTask) {
					it.remove();
					return;
				}
			}
		}
	}

	private class TaskGroupScheduledRunnable implements Runnable {
		private GTaskGroup group;
		private List<GScheduledTask> tasks;

		TaskGroupScheduledRunnable(GTaskGroup group) {
			this.group = group;
			tasks = group.getTasks();// get the tasks out now, in case they change by
										// the time our runnable runs.
		}

		@Override
		public void run() {
			waitingList.add(new GroupInfo(group));
			for (GScheduledTask gScheduledTask : tasks) {
				waitingList.add(new TaskInfo(gScheduledTask));
			}
		}
	}

	private class TaskScheduledRunnable implements Runnable {
		private GScheduledTask task;

		TaskScheduledRunnable(GScheduledTask task) {
			this.task = task;
		}

		@Override
		public void run() {
			boolean animateBackground =
				useAnimations && (!waitingList.isEmpty() || !runningList.isEmpty());
			TaskInfo element = new TaskInfo(task, animateBackground);
			ListIterator<AbstractTaskInfo> listIterator = waitingList.listIterator();
			while (listIterator.hasNext()) {
				AbstractTaskInfo nextElement = listIterator.next();
				if (element.compareTo(nextElement) < 0) {
					listIterator.previous();
					listIterator.add(element);
					return;
				}
			}
			waitingList.addLast(element);
		}
	}

	private class TaskGroupStartedRunnable implements Runnable {
		private GTaskGroup group;

		TaskGroupStartedRunnable(GTaskGroup group) {
			this.group = group;
		}

		@Override
		public void run() {
			AbstractTaskInfo first = waitingList.removeFirst();
			if (first.getGroup() != group) {
				first = waitingList.removeFirst();
			}
			if (first.getGroup() != group) {
				throw new AssertException("Top waiting item should have been new group");
			}
			GProgressBar progressBar = first.setRunning();
			group.getTaskMonitor().setProgressBar(progressBar);
			// important to setCancelledListener after setting ProgressBar as setting 
			//   ProgressBar resets cancelledListener
			progressBar.setCancelledListener(new GroupCancelledListener(group));
			if (group.wasCancelled()) {
				progressBar.initialize(1);
				progressBar.setMessage("CANCELLED!");
			}
			runningList.add(first);
		}
	}

	private class TaskGroupCompletedRunnable implements Runnable {
		private GTaskGroup completedGroup;

		TaskGroupCompletedRunnable(GTaskGroup group) {
			this.completedGroup = group;
		}

		@Override
		public void run() {
			Iterator<AbstractTaskInfo> it = runningList.iterator();
			while (it.hasNext()) {
				AbstractTaskInfo info = it.next();
				GTaskGroup group = info.getGroup();
				if (group == completedGroup && (info instanceof GroupInfo)) {
					if (useAnimations) {
						scrollAwayList.add(info);
						startScrollingAwayAnimation(2000);
					}
					else {
						it.remove();
					}
					return;
				}
			}
			it = waitingList.iterator();
			while (it.hasNext()) {
				AbstractTaskInfo info = it.next();
				GTaskGroup group = info.getGroup();
				if (group == completedGroup && (info instanceof GroupInfo)) {
					it.remove();
					return;
				}
			}
		}
	}

	private class GroupCancelledListener implements CancelledListener {
		private GTaskGroup group;

		GroupCancelledListener(GTaskGroup group) {
			this.group = group;
		}

		@Override
		public void cancelled() {
			taskManager.cancelRunningGroup(group);
		}

	}
}
