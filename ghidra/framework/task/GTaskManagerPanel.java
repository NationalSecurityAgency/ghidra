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
package ghidra.framework.task;

import ghidra.framework.task.gui.GTaskResultPanel;
import ghidra.framework.task.gui.taskview.TaskViewer;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.border.Border;

/**
 * Main component for managing and viewing the state of a GTaskManager.
 * <P>
 * This component consists of three sub-components: the TaskViewer, The GTaskResultPanel, and a
 * button control panel.
 * <P>
 * <U>The TaskViewer:</U><BR>
 * The TaskViewer shows the state of the scheduled and currently running tasks.  It consists of 
 * group objects and task objects arranged in a linear list.  
 * <P>
 * The currently running group has a
 * progress bar that indicates the percentage of completed tasks within that group and has a cancel
 * button that can be used to cancel all tasks within that group.
 * <P>
 * The currently running task has a progress bar the indicates just the progress of that task.  It
 * also has a cancel button that can be used to cancel that task.
 * <P>
 * As groups and tasks are completed, they are removed from the TaskViewer and their results will
 * show up in the result panel (if showing)
 * <P>
 * <U>The GTaskResultPanel</U><BR>
 * The result panel shows the last N tasks that were completed.  It indicates if the task completed
 * successfully, or was cancelled or had an exception.
 * <P>
 * <U>The Button Panel</U><BR>
 * There are buttons to pause and resume the TaskManager, step (run one task when paused), and 
 * cancel all scheduled tasks.
 * 
 */
public class GTaskManagerPanel extends JPanel {

	private GTaskManager taskManager;
	private TaskViewer taskViewer;
	private JSplitPane mainPanel;
	private GTaskResultPanel resultPanel;
	private float lastDividerLocation = 0.67f;

	public GTaskManagerPanel(GTaskManager taskMgr) {
		this.taskManager = taskMgr;
		setLayout(new BorderLayout());

		Border emptyBorder = BorderFactory.createEmptyBorder(5, 5, 0, 5);
		taskViewer = new TaskViewer(taskMgr);
		resultPanel = new GTaskResultPanel(taskMgr);
		resultPanel.setBorder(BorderFactory.createTitledBorder(emptyBorder, "Task Results"));
		mainPanel = new JSplitPane();
		mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 5));
		JComponent taskViewerComponent = taskViewer.getComponent();
		taskViewerComponent.setBorder(BorderFactory.createTitledBorder(emptyBorder,
			"Scheduled Tasks"));
		mainPanel.setLeftComponent(taskViewerComponent);
		mainPanel.setRightComponent(resultPanel);
		mainPanel.remove(resultPanel);
		mainPanel.setResizeWeight(.55);

		add(mainPanel, BorderLayout.CENTER);
		add(buildControlPanel(), BorderLayout.SOUTH);

	}

	/**
	 * Turns on or off animations.
	 * @param b if true, the component will use animation.
	 */
	public void setUseAnimations(boolean b) {
		taskViewer.setUseAnimations(b);
	}

	/**
	 * Turns on or off the display of the task results panel.
	 * @param b if true, displays the task results panel.
	 */
	public void showResultPanel(boolean b) {
		if (b) {
			mainPanel.setRightComponent(resultPanel);
			mainPanel.setDividerLocation(lastDividerLocation);
			mainPanel.invalidate();
		}
		else {
			int dividerLocation = mainPanel.getDividerLocation();
			Dimension size = mainPanel.getSize();
			int width = Math.max(1, size.width);
			lastDividerLocation = (float) dividerLocation / (float) width;
			mainPanel.remove(resultPanel);
		}
		validate();
	}

	private Component buildControlPanel() {
		JPanel panel = new JPanel(new FlowLayout());

		JButton pauseButton = new JButton("Pause");
		JButton resumeButton = new JButton("Resume");
		JButton stepButton = new JButton("Step");
		JButton clearButton = new JButton("Clear All");

		pauseButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				pause();
			}
		});
		resumeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				resume();
			}
		});
		stepButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				step();
			}
		});
		clearButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				clear();
			}
		});

		panel.add(pauseButton);
		panel.add(stepButton);
		panel.add(resumeButton);
		panel.add(clearButton);
		return panel;
	}

	// overridden to include size for initially invisible result panel.
	@Override
	public Dimension getPreferredSize() {
		Dimension preferredSize = super.getPreferredSize();
		Dimension resultSize = resultPanel.getPreferredSize();
		return new Dimension(preferredSize.width + resultSize.width, preferredSize.height);
	}

	private void clear() {
		taskManager.cancelAll();
	}

	private void step() {
		taskManager.runNextTaskEvenWhenSuspended();
	}

	private void resume() {
		taskManager.setSuspended(false);
	}

	private void pause() {
		taskManager.setSuspended(true);
	}
}
