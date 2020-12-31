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
package docking.widgets.table.threaded;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.*;

import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorComponent;
import resources.Icons;

/**
 * A convenience component designed specifically for rendering threaded table models.
 * This panel will automatically create a threaded table and a task monitor component.
 * 
 * @param <T> the type
 */
public class GThreadedTablePanel<T> extends JPanel {

	private static final int SHOW_PROGRESS_DEFAULT = 1000;
	private static final int MIN_UPDATE_DELAY = 1000;
	private static final int MAX_UPDATE_DELAY = 5 * 60 * 1000;
	private static final int MIN_INCREMENTAL_UPDATE_DELAY = 250;
	private static final int MAX_INCREMENTAL_UPDATE_DELAY = 2000;

	private GTable table;
	private ThreadedTableModel<T, ?> threadedModel;
	private ThreadedTableModelListener tableListener;

	private MessagePassingTaskMonitor defaultMonitor;
	private IncrementalLoadingTaskMonitor incrementalMonitor;
	private JPanel pendingPanel;

	/** The progress monitor that shows the loading process (defined dynamically, based on model) */
	private TaskMonitorComponent loadingProgressMonitor;

	/** The monitor loaded into the GUI */
	private JComponent loadedComponent;
	private EmptyBorderButton refreshButton;

	private Timer showTimer;
	private Runnable showProgressRunnable = () -> startShowProgressTimer();

	private Runnable showPendingRunnable = () -> doShowPendingPanel();

	private Runnable updateCompleteRunnable = () -> doUpdateComplete();

	private final int minUpdateDelay;
	private final int maxUpdateDelay;

	/**
	 * Constructs a new threaded table panel.
	 * @param model the threaded table model
	 */
	public GThreadedTablePanel(ThreadedTableModel<T, ?> model) {
		this(model, getMinDelay(model), getMaxDelay(model));
	}

	/**
	 * Constructs a new threaded table panel.
	 * @param model the threaded table model
	 * @param minUpdateDelay the minimum amount of time to wait before the table model will
	 *        update its data
	 */
	public GThreadedTablePanel(ThreadedTableModel<T, ?> model, int minUpdateDelay) {
		this(model, minUpdateDelay, getMaxDelay(model));
	}

	/**
	 * Constructs a new threaded table panel.
	 * @param model the threaded table model
	 * @param minUpdateDelay the minimum amount of time to wait before the table model will
	 *        update its data
	 * @param maxUpdateDelay the maximum amount of time to wait before the table model will
	 *        update its data
	 */
	public GThreadedTablePanel(ThreadedTableModel<T, ?> model, int minUpdateDelay,
			int maxUpdateDelay) {
		super(new BorderLayout());
		this.threadedModel = model;
		this.minUpdateDelay = minUpdateDelay;
		this.maxUpdateDelay = maxUpdateDelay;
		buildPending();

		table = createTable(model);
		initializeModel(model);
		add(new JScrollPane(table), BorderLayout.CENTER);
	}

	protected GTable createTable(ThreadedTableModel<T, ?> model) {
		return new GTable(model);
	}

	private void initializeModel(ThreadedTableModel<T, ?> model) {
		defaultMonitor = new MessagePassingTaskMonitor();
		incrementalMonitor = new IncrementalLoadingTaskMonitor(defaultMonitor);

		if (threadedModel.isLoadIncrementally()) {
			defaultMonitor.setMessageRecipient(incrementalMonitor);
			loadingProgressMonitor = incrementalMonitor;
			model.setIncrementalTaskMonitor(incrementalMonitor);
		}
		else {
			loadingProgressMonitor = defaultMonitor;
		}

		tableListener = new TableListener();
		model.addThreadedTableModelListener(tableListener);

		model.setDefaultTaskMonitor(defaultMonitor);
		model.setUpdateDelay(minUpdateDelay, maxUpdateDelay);
		threadedModel = model;
	}

	public void setModel(ThreadedTableModel<T, ?> model) {
		initializeModel(model);
		table.setModel(model);
	}

	public void dispose() {
		table.dispose();
	}

	public TaskMonitor getTaskMonitor() {
		return loadingProgressMonitor;
	}

	public void refresh() {
		threadedModel.reload();
	}

	public boolean isBusy() {
		return threadedModel.isBusy();
	}

	private void buildPending() {
		refreshButton = new EmptyBorderButton(Icons.REFRESH_ICON);
		refreshButton.addActionListener(e -> threadedModel.reload());
		refreshButton.setToolTipText("Force Refresh Now");
		pendingPanel = new JPanel(new FlowLayout());
		pendingPanel.setName("Pending Panel");
		pendingPanel.add(new GLabel("Update pending...", SwingConstants.CENTER),
			BorderLayout.CENTER);
		pendingPanel.add(refreshButton, BorderLayout.EAST);
	}

	/**
	 * Returns the underlying table
	 * @return the table
	 */
	public GTable getTable() {
		return table;
	}

	private void handleUpdatePending() {
		Swing.runLater(showPendingRunnable);
	}

	private void handleUpdating() {
		Swing.runLater(showProgressRunnable);
	}

	private void handleUpdateComplete() {
		Swing.runLater(updateCompleteRunnable);
	}

	private void doUpdateComplete() {
		incrementalMonitor.reset();
		if (showTimer != null) {
			showTimer.stop();
		}

		doHideProgressPanel();
	}

	private void startShowProgressTimer() {
		showTimer = new Timer(SHOW_PROGRESS_DEFAULT, ev -> {
			if (isBusy()) {
				showTimer = null;
				doShowProgressPanel();
			}
		});
		showTimer.setInitialDelay(SHOW_PROGRESS_DEFAULT);
		showTimer.setRepeats(false);
		showTimer.start();
	}

	private void doShowProgressPanel() {
		// we have an incremental model, see if the table is actually loading, or just performing
		// some kind of user operation, like sorting
		if (threadedModel.isLoading()) {
			doShowLoadingProgressPanel();
		}
		else {
			doShowNonLoadingProgressPanel();
		}
	}

	private void doShowLoadingProgressPanel() {
		if (loadedComponent != null) {
			remove(loadedComponent);
			loadedComponent = null;
		}

		loadedComponent = loadingProgressMonitor;
		add(loadedComponent, BorderLayout.SOUTH);
		loadedComponent.invalidate();

		table.invalidate();
		validate();
		repaint();
	}

	private void doShowNonLoadingProgressPanel() {
		if (loadedComponent != null) {
			remove(loadedComponent);
			loadedComponent = null;
		}

		loadedComponent = defaultMonitor;
		add(loadedComponent, BorderLayout.SOUTH);
		loadedComponent.invalidate();

		table.invalidate();
		validate();
		repaint();
	}

	private void doHideProgressPanel() {
		if (loadedComponent != null) {
			remove(loadedComponent);
			loadedComponent = null;
		}

		table.invalidate();
		validate();
		repaint();
	}

	private void doShowPendingPanel() {
		if (loadedComponent != null) {
			remove(loadedComponent);
		}

		loadedComponent = pendingPanel;
		refreshButton.clearBorder();
		add(loadedComponent, BorderLayout.SOUTH);
		loadedComponent.invalidate();
		table.invalidate();

		validate();
		repaint();
	}

//==================================================================================================
// Inner Classes (and miscellanea/gallimaufry)
//==================================================================================================

	/**
	 * A task monitor component that will pass message onto the task monitor that it has been 
	 * given.  This monitor will be used in one of two different ways: 1) if not loading 
	 * incrementally, then this model will appear in the GUI and will be used by the threaded 
	 * model while loading for incrementing progress; and 2)  when loading incrementally, this 
	 * monitor will not appear in the GUI, but is still used internally by the threaded model
	 * to allow cancelling and to report progress.    
	 * <p>
	 * This class is useful when we are loading incrementally and are displaying the 
	 * {@link IncrementalLoadingTaskMonitor}, but would like messages to this monitor to appear
	 * in the GUI.
	 */
	private class MessagePassingTaskMonitor extends TaskMonitorComponent {
		private TaskMonitorComponent messageRecepientMonitor;

		public MessagePassingTaskMonitor() {
			setName("Basic Task Monitor Component");
		}

		@Override
		public synchronized void setMessage(String message) {
			super.setMessage(message);

			if (messageRecepientMonitor != null) {
				messageRecepientMonitor.setMessage(message);
			}
		}

		void setMessageRecipient(TaskMonitorComponent monitor) {
			messageRecepientMonitor = monitor;
		}
	}

	/**
	 * This task monitor is shown in the GUI when the given threaded model of this class is
	 * loading incrementally (see {@link ThreadedTableModel#isLoadIncrementally()}.
	 */
	private class IncrementalLoadingTaskMonitor extends TaskMonitorComponent {

		private final TaskMonitorComponent defaultMonitorComponent;

		public IncrementalLoadingTaskMonitor(TaskMonitorComponent defaultMonitor) {
			defaultMonitorComponent = defaultMonitor;
			setName("Incremental Task Monitor Component");
		}

		@Override
		public synchronized void setMessage(String message) {
			super.setMessage("[Loading Incrementally] " + message);
		}

		@Override
		public void cancel() {
			// cancel the monitor used internally by the threaded model, which is in a different
			// thread than the thread loading incrementally
			defaultMonitorComponent.cancel();
			super.cancel();
		}
	}

	private class TableListener implements ThreadedTableModelListener {
		@Override
		public void loadPending() {
			handleUpdatePending();
		}

		@Override
		public void loadingStarted() {
			handleUpdating();
		}

		@Override
		public void loadingFinished(boolean wasCancelled) {
			handleUpdateComplete();
		}
	}

	private static int getMinDelay(ThreadedTableModel<?, ?> model) {
		return model.isLoadIncrementally() ? MIN_INCREMENTAL_UPDATE_DELAY : MIN_UPDATE_DELAY;
	}

	private static int getMaxDelay(ThreadedTableModel<?, ?> model) {
		return model.isLoadIncrementally() ? MAX_INCREMENTAL_UPDATE_DELAY : MAX_UPDATE_DELAY;
	}
}
