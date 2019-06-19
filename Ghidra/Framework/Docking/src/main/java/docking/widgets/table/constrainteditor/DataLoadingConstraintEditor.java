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
/**
 *
 */
package docking.widgets.table.constrainteditor;

import java.awt.*;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import javax.swing.*;

import docking.DisabledComponentLayerFactory;
import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.ColumnData;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.layout.ColumnLayout;
import ghidra.util.task.*;
import resources.Icons;

/**
 * Abstract base class for constraint editors that load all the data in a column in order to
 * initialize themselves.
 *
 * @param <T> the column type
 */
public abstract class DataLoadingConstraintEditor<T> extends AbstractColumnConstraintEditor<T>
		implements TaskListener {

	private TaskMonitorComponent taskMonitorComponent;

	private JButton reloadDataButton;

	protected final ColumnData<T> columnDataSource;

	private boolean hasLoaded = false;
	private boolean hasInlineEditorComponent = false;

	private static final String TASK_VIEW = "Task";
	private static final String EDITOR_VIEW = "Editor";
	private JPanel viewPanel;
	private CardLayout viewLayout;

	private JLayer<?> detailEditorDisableLayer = null;

	protected JLabel statusLabel;

	/**
	 * Constructor.
	 *
	 * @param delegateConstraint the constraint to feed column data to. Provides
	 * editors for manipulating constraint values.
	 * @param columnDataSource provides access to table data and. Must be non-null.
	 */
	public DataLoadingConstraintEditor(ColumnConstraint<T> delegateConstraint,
			ColumnData<T> columnDataSource) {
		super(delegateConstraint);

		Objects.requireNonNull(columnDataSource, "columnDataSource must be non-null");

		this.columnDataSource = columnDataSource;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * This editor provides a panel containing a {@link TaskMonitorComponent} and the ability
	 * to reload the columns' data; if the delegate editor provides an inline editor, this
	 * wraps it, and switches between task view and the editor depending on the executing
	 * state of the data-load task.
	 *
	 * @see DataLoadingConstraintEditor#buildDelegateInlineEditor()
	 */
	@Override
	protected Component buildInlineEditorComponent() {
		JPanel editorPanel = new JPanel(new BorderLayout());
		statusLabel = new GDHtmlLabel();
		statusLabel.setHorizontalAlignment(SwingConstants.CENTER);

		taskMonitorComponent = new TaskMonitorComponent();

		reloadDataButton = new EmptyBorderButton(Icons.REFRESH_ICON);
		reloadDataButton.setToolTipText("Reload column data");
		reloadDataButton.addActionListener(e -> loadData());

		viewLayout = new CardLayout();
		viewPanel = new JPanel(viewLayout);
		viewPanel.add(taskMonitorComponent, TASK_VIEW);

		Component editorComponent = buildDelegateInlineEditor();
		if (editorComponent != null) {
			editorPanel.add(editorComponent, BorderLayout.CENTER);
			viewPanel.add(editorPanel, EDITOR_VIEW);
			hasInlineEditorComponent = true;
		}

		JPanel buttonPanel = new JPanel(new ColumnLayout(2, 2, 1));
		buttonPanel.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
		buttonPanel.add(reloadDataButton);

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(viewPanel, BorderLayout.CENTER);
		panel.add(buttonPanel, BorderLayout.EAST);
		panel.add(statusLabel, BorderLayout.SOUTH);
		return panel;
	}

	/**
	 * Get the delegates' inline editor component
	 * @return the inline editor for the delegate constraint
	 */
	protected Component buildDelegateInlineEditor() {
		return null;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * @see DataLoadingConstraintEditor#buildDelegateDetailEditor()
	 */
	@Override
	protected Component buildDetailEditorComponent() {
		Component comp = buildDelegateDetailEditor();

		if (comp == null) {
			if (!hasInlineEditorComponent) {
				throw new IllegalStateException("Constraint must provide an editor component");
			}
			return null;
		}

		JPanel editorWrapper = new JPanel(new BorderLayout());

		editorWrapper.add(comp, BorderLayout.CENTER);

		if (comp instanceof JComponent) {
			detailEditorDisableLayer =
				DisabledComponentLayerFactory.getDisabledLayer((JComponent) comp);
			editorWrapper.add(detailEditorDisableLayer);
		}

		return editorWrapper;
	}

	/**
	 * Get the delegates' detail component
	 * @return the detail editor for the delegate constraint
	 */
	protected Component buildDelegateDetailEditor() {
		return null;
	}

	/**
	 * A value has been read from the table (column); handle it in an
	 * editor-specific way.
	 * @param value the value read from the table (column)
	 */
	public abstract void handleColumnDataValue(T value);

	/**
	 * Notification that the column data-load has been completed.
	 */
	public void columnDataLoadComplete() {
		Msg.info(this, "Load Complete!");
	}

	/**
	 * Notification that the column data-load was cancelled.
	 */
	public void columnDataLoadCancelled() {
		reset();
	}

	/**
	 * Request that any state maintained by the delegate editor pertaining to
	 * column data be cleared.
	 */
	public void clearColumnData() {
		// do nothing; left for subclasses to implement
	}

	private void showTaskView() {
		viewLayout.show(viewPanel, TASK_VIEW);

		if (detailEditorDisableLayer != null) {
			detailEditorDisableLayer.setEnabled(false);
		}
	}

	private void showEditorView() {
		viewLayout.show(viewPanel, EDITOR_VIEW);

		if (detailEditorDisableLayer != null) {
			detailEditorDisableLayer.setEnabled(true);
		}
	}

	private void loadData() {

		showTaskView();

		clearColumnData();

		reloadDataButton.setVisible(false);
		Task task = new LoadDataTask();
		task.addTaskListener(this);

		TaskBuilder.withTask(task).launchInBackground(taskMonitorComponent);
	}

	@Override
	public void reset() {
		hasLoaded = false;
		clearColumnData();

		resetEditor();

		loadData();
	}

	/**
	 * Reset the delegate editor to a known state
	 * @see #reset()
	 */
	protected abstract void resetEditor();

	@Override
	protected abstract ColumnConstraint<T> getValueFromComponent();

	@Override
	public String getErrorMessage() {
		return "Data load required";
	}

	@Override
	protected void updateEditorComponent() {
		if (!hasLoaded) {
			loadData();
		}
		doUpdateEditorComponent();
	}

	/**
	 * Indicates the constraint has changed, and the user interface needs to be updated to reflect
	 * the new state.
	 */
	protected abstract void doUpdateEditorComponent();

	@Override
	public void taskCompleted(Task task) {
		reloadDataButton.setVisible(true);

		// There may be a case where this is visible after the task is completed.  Maybe remove
		// in the future.
		taskMonitorComponent.setMessage("<html>" + HTMLUtilities.bold("Ready"));

		hasLoaded = true;

		columnDataLoadComplete();

		showEditorView();

		valueChanged();
	}

	@Override
	public void taskCancelled(Task task) {
		reloadDataButton.setVisible(true);
		hasLoaded = false;

		columnDataLoadCancelled();

		showEditorView();
		taskMonitorComponent.reset();
		valueChanged();

	}

	private class LoadDataTask extends Task {

		public LoadDataTask() {
			super("Load column data", true, true, true, true);

		}

		private long elapsedNanosIn(long elapsedNanos, TimeUnit unit) {
			return unit.convert(elapsedNanos, TimeUnit.NANOSECONDS);
		}

		private String getElapsedTimeString(long elapsedNanos) {

			long hours = elapsedNanosIn(elapsedNanos, TimeUnit.HOURS);
			long minutes = elapsedNanosIn(elapsedNanos, TimeUnit.MINUTES) - (hours * 60);
			long seconds = elapsedNanosIn(elapsedNanos, TimeUnit.SECONDS) - (minutes * 60);

			if (hours != 0) {
				return String.format("%d:%02d:%02d", hours, minutes, seconds);
			}

			return String.format("%02d:%02d", minutes, seconds);
		}

		@Override
		public void run(TaskMonitor monitor) {

			long start = System.nanoTime();

			int limit = columnDataSource.getCount();

			monitor.initialize(limit);
			monitor.setIndeterminate(false);
			monitor.setMessage("Loading column data...");

			for (int i = 0; i < limit; i++) {
				if (monitor.isCancelled()) {
					return;
				}

				T val = columnDataSource.getColumnValue(i);
				handleColumnDataValue(val);

				long elapsed = System.nanoTime() - start;

				monitor.setMessage(
					"Loading column data... (" + getElapsedTimeString(elapsed) + ")");
				monitor.incrementProgress(1);

			}
// 		Keep until 2019
//			Msg.info(this, "Load of " + limit + " rows from '" + columnDataSource.getColumnName() +
//				"' took " + getElapsedTimeString(System.nanoTime() - start));

		}
	}
}
