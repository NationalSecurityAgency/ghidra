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

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

import javax.swing.*;

import docking.framework.DockingApplicationConfiguration;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import generic.concurrent.GThreadPool;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TaskSimulator {
	private JRadioButton lowButton;
	private JRadioButton mediumButton;
	private JRadioButton highButton;
	private JRadioButton urgentButton;
	private JCheckBox yieldingCheckbox;
	public int nextTaskID;
	private GTaskManager taskMgr;
	protected boolean showingResults;
	private JPanel mainPanel;
	private JFrame jFrame;

	public TaskSimulator() throws IOException {
		GThreadPool threadPool = GThreadPool.getSharedThreadPool("Test Thread Pool");
		GenericDomainObjectDB domainObj = new GenericDomainObjectDB(this);
		taskMgr = new GTaskManager(domainObj, threadPool);
		taskMgr.setSuspended(true);
		taskPanel = new GTaskManagerPanel(taskMgr);
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(taskPanel, BorderLayout.CENTER);
		jFrame = new JFrame("Test");
		jFrame.getContentPane().setLayout(new BorderLayout());
		jFrame.getContentPane().add(mainPanel, BorderLayout.CENTER);

		jFrame.getContentPane().add(buildUserPanel(), BorderLayout.SOUTH);
		jFrame.pack();
		jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		jFrame.setLocation(new Point(3000, 200));
		jFrame.setVisible(true);

	}

	private Component buildUserPanel() {
		JPanel panel = new JPanel(new BorderLayout());

		JButton addGroupButton = new JButton("Add Group");
		JButton addTaskButton = new JButton("Add Task");
		JButton showResultsButton = new JButton("Show Results");
		lowButton = new GRadioButton("Low");
		mediumButton = new GRadioButton("Medium");
		highButton = new GRadioButton("High");
		urgentButton = new GRadioButton("Urgent");
		ButtonGroup group = new ButtonGroup();
		group.add(lowButton);
		group.add(mediumButton);
		group.add(highButton);
		group.add(urgentButton);
		mediumButton.setSelected(true);

		yieldingCheckbox = new GCheckBox("Yielding");

		addGroupButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				addGroup();
			}
		});
		addTaskButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				addTask();
			}
		});
		showResultsButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (showingResults) {
					showingResults = false;
					removeResultsPanel();
				}
				else {
					showingResults = true;
					addResultsPanel();
				}
			}
		});

		JPanel topPanel = new JPanel(new FlowLayout());
		JPanel bottomPanel = new JPanel(new FlowLayout());

		topPanel.add(addGroupButton);
		topPanel.add(addTaskButton);
		topPanel.add(showResultsButton);

		bottomPanel.add(lowButton);
		bottomPanel.add(mediumButton);
		bottomPanel.add(highButton);
		bottomPanel.add(urgentButton);
		bottomPanel.add(yieldingCheckbox);

		panel.add(topPanel, BorderLayout.NORTH);
		panel.add(bottomPanel, BorderLayout.SOUTH);
		return panel;
	}

	protected void addResultsPanel() {
		taskPanel.showResultPanel(true);
	}

	protected void removeResultsPanel() {
		taskPanel.showResultPanel(false);
	}

	protected void addTask() {
		boolean yield = yieldingCheckbox.isSelected();
		MyTask myTask = new MyTask(10, yield);
		int priority = getPriority();
		taskMgr.scheduleTask(myTask, priority, true);
	}

	private int getPriority() {
		if (urgentButton.isSelected()) {
			return 1;
		}
		if (highButton.isSelected()) {
			return 10;
		}
		if (mediumButton.isSelected()) {
			return 20;
		}
		return 30;
	}

	static int nextGroupID = 1;
	private GTaskManagerPanel taskPanel;

	protected void addGroup() {
		GTaskGroup group = new GTaskGroup("Group " + (nextGroupID++), true);
		for (int i = 0; i < 4; i++) {
			MyTask myTask = new MyTask(10, false);
			group.addTask(myTask, i * 10);
		}
		taskMgr.scheduleTaskGroup(group);
	}

	public static void main(String[] args) throws IOException {
		Application.initializeApplication(new GhidraApplicationLayout(),
			new DockingApplicationConfiguration());
		new TaskSimulator();

	}

	class MyTask implements GTask {
		int id = nextTaskID++;
		private int count;
		private boolean yielding;

		MyTask(int count, boolean yielding) {
			this.count = count;
			this.yielding = yielding;

		}

		@Override
		public String getName() {
			return "Task " + id;
		}

		@Override
		public void run(UndoableDomainObject domainObject, TaskMonitor monitor)
				throws CancelledException {

			monitor.initialize(count);

			for (int i = 0; i < count; i++) {
				monitor.checkCanceled();
				try {
					Thread.sleep(1000);
				}
				catch (InterruptedException e) {
					e.printStackTrace();
				}
				monitor.setMessage("Completed " + (i + 1) + " of " + count);
				monitor.incrementProgress(1);
				if (yielding) {
					taskMgr.waitForHigherPriorityTasks();
				}
			}

		}
	}

}
