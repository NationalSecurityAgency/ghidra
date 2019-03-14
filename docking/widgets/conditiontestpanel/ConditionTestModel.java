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
package docking.widgets.conditiontestpanel;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

import javax.swing.SwingUtilities;

public class ConditionTestModel {
	private ArrayList<ConditionTester> tests;
	private Map<ConditionTester, ConditionTestState> map;

	private final ConditionTestPanel conditionTestPanel;
	private int completedTestCount = 0;
	private int errorCount = 0;
	private int warningCount = 0;
	private volatile ConditionTestRunner conditionTestRunner;
	private ConditionTester inProgressTest;
	private int skippedCount;

	public ConditionTestModel(ConditionTestPanel conditionTestPanel, List<ConditionTester> tests) {
		this.conditionTestPanel = conditionTestPanel;
		this.tests = new ArrayList<ConditionTester>(tests);
		map = new HashMap<ConditionTester, ConditionTestState>();

		for (ConditionTester conditionTest : tests) {
			ConditionTestState testState = new ConditionTestState(conditionTest);
			map.put(conditionTest, testState);
		}
	}

	public synchronized void runTests(TaskMonitor monitor) {
		if (conditionTestRunner != null) {
			return;
		}
		for (ConditionTester test : tests) {
			ConditionTestState testState = map.get(test);
			testState.setResult(null);
		}
		completedTestCount = 0;
		errorCount = 0;
		warningCount = 0;
		skippedCount = 0;
		updatePanel();
		conditionTestRunner = new ConditionTestRunner(monitor);
	}

	public void skipTests() {
		if (conditionTestRunner != null) {
			return;
		}
		for (ConditionTester test : tests) {
			ConditionTestState testState = map.get(test);
			testState.setResult(new ConditionResult(ConditionStatus.Skipped));
		}
		completedTestCount = tests.size();
		errorCount = 0;
		warningCount = 0;
		skippedCount = tests.size();
		notifyTestsCompleted();
	}

	public int getTestCount() {
		return tests.size();
	}

	public int getCompletedTestCount() {
		return completedTestCount;
	}

	public int getWarningCount() {
		return warningCount;
	}

	public int getErrorCount() {
		return errorCount;
	}

	public int getSkippedCount() {
		return skippedCount;
	}

	synchronized void conditionTestCompleted() {
		conditionTestRunner = null;
		notifyTestsCompleted();
	}

	synchronized void startingTest(ConditionTester test) {
		inProgressTest = test;
		updatePanel();
	}

	synchronized void endingTest(ConditionTester test, ConditionResult result) {
		inProgressTest = null;
		ConditionTestState state = map.get(test);
		state.setResult(result);
		ConditionStatus status = result.getStatus();
		if (status == ConditionStatus.Error) {
			errorCount++;
		}
		else if (status == ConditionStatus.Warning || status == ConditionStatus.Cancelled) {
			warningCount++;
		}
		else if (status == ConditionStatus.Skipped) {
			skippedCount++;
		}
		completedTestCount++;
		updatePanel();
	}

	public void skippingTest(ConditionTester test) {
		ConditionResult result = new ConditionResult(ConditionStatus.Skipped);
		endingTest(test, result);
	}

	private void notifyTestsCompleted() {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				conditionTestPanel.testsCompleted();
			}
		});
	}

	private void updatePanel() {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				conditionTestPanel.update();
			}
		});
	}

	public List<ConditionTester> getTests() {
		return new ArrayList<ConditionTester>(tests);
	}

	public ConditionStatus getStatus(ConditionTester test) {
		ConditionTestState conditionTestState = map.get(test);
		return conditionTestState.getStatus();
	}

	public synchronized boolean isInProgress() {
		return conditionTestRunner != null;
	}

	public boolean isInProgress(ConditionTester test) {
		return test == inProgressTest;
	}

	public void setEnabled(ConditionTester test, boolean enabled) {
		ConditionTestState conditionTestState = map.get(test);
		conditionTestState.setEnabled(enabled);
	}

	public String getStatusMessage(ConditionTester test) {
		ConditionTestState conditionTestState = map.get(test);
		return conditionTestState.getStatusMessage();
	}

	synchronized void cancel() {
		if (conditionTestRunner != null) {
			conditionTestRunner.dispose();
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class ConditionTestRunner extends Thread {
		private final TaskMonitor monitor;
		private boolean isDisposed;

		ConditionTestRunner(TaskMonitor monitor) {
			this.monitor = monitor;
			start();
		}

		@Override
		public void run() {
			for (ConditionTester test : tests) {
				if (isDisposed) {
					return;
				}

				monitor.clearCanceled();
				monitor.setMessage("");
				monitor.setProgress(0);
				ConditionTestState conditionTestState = map.get(test);
				if (conditionTestState.isEnabled()) {
					startingTest(test);
					ConditionResult result;
					try {
						result = test.run(monitor);
					}
					catch (CancelledException e) {
						result = new ConditionResult(ConditionStatus.Cancelled);
					}
					endingTest(test, result);
				}
				else {
					skippingTest(test);
				}
			}
			conditionTestCompleted();
		}

		void dispose() {
			isDisposed = true;
			monitor.cancel();
		}
	}

}
