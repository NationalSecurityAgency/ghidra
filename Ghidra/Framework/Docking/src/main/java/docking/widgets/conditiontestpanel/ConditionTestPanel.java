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
package docking.widgets.conditiontestpanel;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;

import docking.widgets.EmptyBorderButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.label.GDLabel;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorComponent;
import resources.ResourceManager;

public class ConditionTestPanel extends JPanel {
	static final Icon ERROR_ICON = ResourceManager.loadImage("images/edit-delete.png");
	static final Icon WARNING_ICON = ResourceManager.loadImage("images/dialog-warning.png");
	static final Icon PASSED_ICON = ResourceManager.loadImage("images/checkmark_green.gif");
	private ConditionTestModel conditionTestModel;
	private TaskMonitorComponent taskMonitor;
	private List<TestPanel> testPanelList = new ArrayList<>();
	private List<TestStatusPanel> testStatusPanelList = new ArrayList<>();
	private JLabel runsLabel;
	private JLabel errorsLabel;
	private JLabel warningsLabel;
	private OverallProgressBar overallProgressBar;
	private JLabel detailsLabel;
	private ConditionTester selectedTest;
	final HashSet<ConditionTestListener> listeners = new HashSet<>();

	public ConditionTestPanel(List<ConditionTester> tests) {
		super(new BorderLayout());
		conditionTestModel = new ConditionTestModel(this, tests);
		add(buildStatusPanel(), BorderLayout.NORTH);
		JSplitPane splitPane =
			new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildTestPanel(), buildDetailsPanel());
		add(splitPane, BorderLayout.CENTER);
		splitPane.setResizeWeight(0.75);
		taskMonitor = new TaskMonitorComponent();
	}

	public void addListener(ConditionTestListener listener) {
		listeners.add(listener);
	}

	public void removeListener(ConditionTestListener listener) {
		listeners.remove(listener);
	}

	public boolean hasRunTests() {
		return conditionTestModel.getCompletedTestCount() == conditionTestModel.getTestCount();
	}

	public boolean isInProgress() {
		return conditionTestModel.isInProgress();
	}

	public int getErrorCount() {
		return conditionTestModel.getErrorCount();
	}

	public int getWarningCount() {
		return conditionTestModel.getWarningCount();
	}

	public int getSkippedCount() {
		return conditionTestModel.getSkippedCount();
	}

	void update() {
		updateSummary();
		updateOverallProgress();
		updateTestStatus();
		updateDetailMessage();
	}

	private void updateDetailMessage() {
		if (selectedTest == null) {
			detailsLabel.setText("");
			return;
		}
		String message = conditionTestModel.getStatusMessage(selectedTest);
		String htmlString = HTMLUtilities.toHTML(message);
		detailsLabel.setText(htmlString);
	}

	private void updateTestStatus() {
		for (TestStatusPanel testStatusPanel : testStatusPanelList) {
			ConditionTester test = testStatusPanel.getTest();
			ConditionStatus status = conditionTestModel.getStatus(test);
			testStatusPanel.setStatus(status);
			testStatusPanel.setInProgress(conditionTestModel.isInProgress(test));
		}
	}

	private void updateOverallProgress() {
		overallProgressBar.setMaxProgress(conditionTestModel.getTestCount());
		overallProgressBar.setProgress(conditionTestModel.getCompletedTestCount());
		Color color = Color.GREEN;
		if (conditionTestModel.getErrorCount() > 0) {
			color = Color.RED;
		}
		else if (conditionTestModel.getWarningCount() > 0) {
			color = Color.YELLOW;
		}
		overallProgressBar.setColor(color);
	}

	private void updateSummary() {
		int testCount = conditionTestModel.getTestCount();
		int completedTestCount = conditionTestModel.getCompletedTestCount();
		runsLabel.setText("Tests: " + completedTestCount + "/" + testCount);

		warningsLabel.setText("Warnings: " + conditionTestModel.getWarningCount());
		errorsLabel.setText("Errors: " + conditionTestModel.getErrorCount());
	}

	private Component buildDetailsPanel() {
		detailsLabel = new ScrollableLabel();

		detailsLabel.setVerticalAlignment(SwingConstants.TOP);
		JScrollPane scroll = new JScrollPane(detailsLabel);
		return scroll;
	}

	private Component buildTestPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		List<ConditionTester> tests = conditionTestModel.getTests();
		for (ConditionTester conditionTest : tests) {
			TestPanel testPanel = new TestPanel(conditionTest);
			TestStatusPanel statusPanel = new TestStatusPanel(conditionTest);
			testPanelList.add(testPanel);
			testStatusPanelList.add(statusPanel);
			panel.add(testPanel);
			panel.add(statusPanel);
		}

		JScrollPane scrollPane = new JScrollPane(panel);
		scrollPane.getVerticalScrollBar().setUnitIncrement(10);

		return scrollPane;
	}

	private Component buildStatusPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(createRunAndSummaryPanel(), BorderLayout.WEST);
		overallProgressBar = new OverallProgressBar();
		panel.add(overallProgressBar);
		return panel;

	}

	public void runTests() {
		conditionTestModel.runTests(taskMonitor);
	}

	public void skipTests() {
		for (TestPanel testPanel : testPanelList) {
			testPanel.checkbox.setSelected(false);
		}
		conditionTestModel.skipTests();
		testsCompleted();
	}

	private Component createRunAndSummaryPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		JButton runButton = new EmptyBorderButton(ResourceManager.loadImage("images/play.png"));
		runButton.addActionListener(e -> conditionTestModel.runTests(taskMonitor));
		JPanel buttonPanel = new JPanel(new BorderLayout());
		buttonPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 0));
		buttonPanel.add(runButton);
		panel.add(buttonPanel, BorderLayout.WEST);
		panel.add(createSummaryPanel());
		return panel;
	}

	private Component createSummaryPanel() {
		JPanel panel = new JPanel(new GridLayout(1, 3, 20, 0));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		runsLabel = new GDLabel("Tests: 0/" + conditionTestModel.getTestCount());
		panel.add(runsLabel);
		errorsLabel = new GDLabel("Errors: 0");
		panel.add(errorsLabel);
		warningsLabel = new GDLabel("Warnings: 0");
		panel.add(warningsLabel);

		return panel;
	}

	void selectTest(ConditionTester test) {
		selectedTest = test;
		for (TestPanel testPanel : testPanelList) {
			testPanel.setSelected(test);
		}
		updateDetailMessage();
	}

	public void testsCompleted() {
		for (ConditionTestListener listener : listeners) {
			listener.testsCompleted();
		}
		update();
		ConditionTester bestTestToSelect = null;
		for (TestPanel testPanel : testPanelList) {
			ConditionTester test = testPanel.getTest();
			ConditionStatus status = conditionTestModel.getStatus(test);
			if (status == ConditionStatus.Error) {
				bestTestToSelect = test;
				break;
			}
			if (status == ConditionStatus.Warning && bestTestToSelect == null) {
				bestTestToSelect = test;
			}
		}
		if (bestTestToSelect != null) {
			selectTest(bestTestToSelect);
		}
	}

	public void cancel() {
		conditionTestModel.cancel();
	}

	public static void main(String[] args) {
		JFrame frame = new JFrame("Test App");
		List<ConditionTester> list = new ArrayList<>();
		list.add(new TestConditionRun("Beta ConfigTest", 20, ConditionStatus.Error,
			"This is an error This is an error This is an error" +
				"This is an error This is an error And this is another line"));
		list.add(new TestConditionRun("Alpha ConfigTest", 15));
		list.add(new TestConditionRun("Gamma  adfda asdfasdf ConfigTest", 50));
		list.add(new TestConditionRun("Zeta ConfigTest", 30, ConditionStatus.Warning,
			"This is a warning"));
		list.add(new TestConditionRun("Delta ConfigTest", 20));
		ConditionTestPanel ctPanel = new ConditionTestPanel(list);
		frame.getContentPane().add(ctPanel);
		frame.pack();
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setVisible(true);

	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ScrollableLabel extends GDHtmlLabel implements Scrollable {

		@Override
		public Dimension getPreferredScrollableViewportSize() {
			return new Dimension(200, 100);
		}

		@Override
		public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 20;
		}

		@Override
		public boolean getScrollableTracksViewportHeight() {
			return false;
		}

		@Override
		public boolean getScrollableTracksViewportWidth() {
			return true;
		}

		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 10;
		}

	}

	private class OverallProgressBar extends JPanel {
		private Color color;
		private int maxProgress;
		private int progress;

		public OverallProgressBar() {
			Border emptyBorder = BorderFactory.createEmptyBorder(10, 15, 10, 5);
			Border bevelBorder = BorderFactory.createBevelBorder(BevelBorder.LOWERED);
			setBorder(BorderFactory.createCompoundBorder(emptyBorder, bevelBorder));
		}

		@Override
		protected void paintComponent(Graphics g) {
			Dimension size = getSize();
			Insets insets = getInsets();
			int x = insets.left;
			int y = insets.top;
			int width = size.width - insets.left - insets.right;
			int height = size.height - insets.top - insets.bottom;
			g.clearRect(x, y, width, height);
			int fillWidth = (int) (((double) progress / (double) maxProgress) * width + .5);
			g.setColor(color);
			g.fillRect(x, y, fillWidth, height);
		}

		@Override
		public Dimension getPreferredSize() {
			return new Dimension(200, 10);
		}

		public void setColor(Color color) {
			this.color = color;
			repaint();
		}

		public void setProgress(int progress) {
			if (progress > maxProgress) {
				progress = maxProgress;
			}
			this.progress = progress;
			repaint();
		}

		public void setMaxProgress(int maxProgress) {
			if (maxProgress <= 0) {
				maxProgress = 1;
			}
			this.maxProgress = maxProgress;
			repaint();
		}
	}

	private class TestPanel extends JPanel {

		private final ConditionTester test;
		private JCheckBox checkbox;
		private JLabel label;
		private Color backgroundColor;
		private Color selectedColor;

		public TestPanel(ConditionTester conditionTest) {
			super(new PairLayout());
			backgroundColor = getBackground();
			selectedColor = Color.LIGHT_GRAY;
			this.test = conditionTest;
			checkbox = new GCheckBox();
			checkbox.setSelected(true);
			add(checkbox);
			label = new GDLabel(test.getName());
			add(label);
			label.setToolTipText(test.getDescription());
			checkbox.addChangeListener(e -> {
				conditionTestModel.setEnabled(test, checkbox.isSelected());
				label.setEnabled(checkbox.isSelected());
			});
			label.addMouseListener(new MouseAdapter() {
				@Override
				public void mousePressed(MouseEvent e) {
					if (!hasRunTests()) {
						checkbox.setSelected(!checkbox.isSelected());
					}
					selectTest(test);
				}
			});
		}

		public void setSelected(ConditionTester selectedTest) {
			boolean isSelected = test == selectedTest;
			setBackground(isSelected ? selectedColor : backgroundColor);
		}

		public ConditionTester getTest() {
			return test;
		}

	}

	private class TestStatusPanel extends JPanel {

		private final ConditionTester test;
		private JLabel label;
		private boolean inProgress;

		public TestStatusPanel(ConditionTester test) {
			super(new BorderLayout());
			this.test = test;
			label = new GDLabel();
			label.setHorizontalAlignment(SwingConstants.LEFT);
			add(label);
		}

		public void setStatus(ConditionStatus status) {
			Icon icon = null;
			switch (status) {
				case Error:
					icon = ERROR_ICON;
					break;
				case Cancelled:
					icon = WARNING_ICON;
					break;
				case Passed:
					icon = PASSED_ICON;
					break;
				case Warning:
					icon = WARNING_ICON;
					break;
				case None:
				case Skipped:
					break;
			}
			label.setIcon(icon);
			repaint();
		}

		@Override
		public Dimension getPreferredSize() {
			return taskMonitor.getPreferredSize();
		}

		public ConditionTester getTest() {
			return test;
		}

		void setInProgress(boolean inProgress) {
			if (this.inProgress == inProgress) {
				return;
			}
			this.inProgress = inProgress;
			removeAll();
			if (inProgress) {
				add(taskMonitor);
			}
			else {
				add(label);
			}
		}
	}

	private static class TestConditionRun implements ConditionTester {

		private final int runIterations;
		private final String name;
		private final ConditionStatus result;
		private final String msg;

		public TestConditionRun(String name, int runIterations) {
			this(name, runIterations, ConditionStatus.Passed, null);
		}

		public TestConditionRun(String name, int runIterations, ConditionStatus result,
				String msg) {
			this.name = name;
			this.runIterations = runIterations;
			this.result = result;
			this.msg = msg;
		}

		@Override
		public String getDescription() {
			return name + " description goes here";
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public ConditionResult run(TaskMonitor monitor) throws CancelledException {
			monitor.initialize(runIterations);
			for (int i = 0; i < runIterations; i++) {
				monitor.setProgress(i);
				try {
					Thread.sleep(100);
				}
				catch (InterruptedException e) {
					// ignore interruption
				}
				monitor.checkCanceled();
			}
			return new ConditionResult(result, msg);
		}

	}

}
