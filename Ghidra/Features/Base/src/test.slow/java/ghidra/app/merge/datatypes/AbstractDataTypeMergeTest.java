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
package ghidra.app.merge.datatypes;

import static org.junit.Assert.*;

import java.awt.*;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.swing.*;

import ghidra.app.merge.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Adapter for data type merge tests.
 */
public abstract class AbstractDataTypeMergeTest extends AbstractMergeTest {

	protected DataTypeMergeManager dataTypeMergeMgr;
	private TaskMonitor testMonitor = new TaskMonitorAdapter();

	protected Window window;

	protected void executeMerge() throws Exception {
		executeMerge(false);
	}

	protected ProgramMultiUserMergeManager createMergeManager(ProgramChangeSet resultChangeSet,
			ProgramChangeSet myChangeSet) {
		return new ProgramMultiUserMergeManager(resultProgram, myProgram, originalProgram,
			latestProgram, resultChangeSet, myChangeSet);
	}

	protected void executeMerge(boolean doWait) throws Exception {

		originalProgram = mtf.getOriginalProgram();
		myProgram = mtf.getPrivateProgram();// my program
		resultProgram = mtf.getResultProgram();// destination program
		latestProgram = mtf.getLatestProgram();// latest version (results and latest start out the same);

		ProgramChangeSet resultChangeSet = mtf.getResultChangeSet();
		ProgramChangeSet myChangeSet = mtf.getPrivateChangeSet();
		mergeMgr = createMergeManager(resultChangeSet, myChangeSet);

		testMonitor.clearCanceled();
		final CountDownLatch started = new CountDownLatch(1);
		final CountDownLatch done = new CountDownLatch(1);
		Thread t = new Thread(() -> {
			try {
				started.countDown();
				mergeMgr.merge(testMonitor);
				done.countDown();
			}
			catch (CancelledException e) {
				// can't happen
			}
		});
		t.start();

		assertTrue("Merge never started",
			started.await(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS));
		waitForSwing();

		window = getMergeWindow(done);

		if (doWait) {
			t.join();
		}
	}

	protected void executeMerge(int option) {
		originalProgram = mtf.getOriginalProgram();
		myProgram = mtf.getPrivateProgram();// my program
		resultProgram = mtf.getResultProgram();// destination program
		latestProgram = mtf.getLatestProgram();// latest version (results and latest start out the same);

		ProgramChangeSet resultChangeSet = mtf.getResultChangeSet();
		ProgramChangeSet myChangeSet = mtf.getPrivateChangeSet();
		ProgramMultiUserMergeManager dummyMergeManager = new DummyMergeManager(resultProgram,
			myProgram, originalProgram, latestProgram, resultChangeSet, myChangeSet);
		DataTypeMergeManager dataTypeMergeManager = new DataTypeMergeManager(dummyMergeManager,
			resultProgram, myProgram, originalProgram, latestProgram, resultChangeSet, myChangeSet);
		if (option >= 0) {
			dataTypeMergeManager.setConflictResolution(option);
		}
		dataTypeMergeManager.merge(TaskMonitor.DUMMY);
	}

	private Window getMergeWindow(CountDownLatch doneLatch) {

		waitForCondition(() -> {
			Window w = getWindowByTitleContaining(null, "Merge Tool");
			boolean isDone = doneLatch.getCount() == 0;
			return w != null || isDone;
		}, "Timed-out waiting for merge window!");

		mergeTool = mergeMgr.getMergeTool();

		return getWindowByTitleContaining(null, "Merge Tool");
	}

	private Window getMergeWindow() {
		Window w = waitForWindowByTitleContaining("Merge Tool");
		mergeTool = mergeMgr.getMergeTool();
		return w;
	}

	protected void chooseOption(int option) throws Exception {

		window = getMergeWindow();

		waitForPreviousApply();

		JRadioButton rb = getButtonForChoice(option);

		assertFalse("Radio button should have been de-selected", rb.isSelected());

		runSwing(() -> rb.setSelected(true));
		waitForSwing();

		JButton applyButton = findButtonByText(window, "Apply");
		assertNotNull(applyButton);
		waitForEnabled(applyButton, true);

		pressButtonByText(window, "Apply");
		waitForSwing();

		// wait until the panel has been reset
		waitForCondition(() -> !applyButton.isEnabled() || !mergeMgr.isMergeToolVisible());
	}

	private JRadioButton getButtonForChoice(int option) {

		JRadioButton rb = waitForValue(() -> {
			if (option == DataTypeMergeManager.OPTION_LATEST) {
				return (JRadioButton) findButton(window, MergeConstants.LATEST_TITLE);
			}
			else if (option == DataTypeMergeManager.OPTION_MY) {
				return (JRadioButton) findButton(window, MergeConstants.MY_TITLE);
			}
			return (JRadioButton) findButton(window, MergeConstants.ORIGINAL_TITLE);
		});

		return rb;
	}

	private void waitForPreviousApply() {
		JRadioButton latestRB = (JRadioButton) findButton(window, MergeConstants.LATEST_TITLE);
		JRadioButton myRB = (JRadioButton) findButton(window, MergeConstants.MY_TITLE);
		JRadioButton origRB = (JRadioButton) findButton(window, MergeConstants.ORIGINAL_TITLE);

		waitForButtonReset(latestRB, false);
		waitForButtonReset(myRB, false);
		waitForButtonReset(origRB, false);
	}

	private void waitForEnabled(JComponent c, boolean enabled) {

		String state = enabled ? "enable" : "disable";
		waitForCondition(() -> c.isEnabled() == enabled,
			"Timed-out waiting for component to " + state + ": " + c.getClass().getSimpleName());
	}

	private void waitForButtonReset(AbstractButton c, boolean selected) {

		if (c == null) {
			return;// not all merge buttons are always on the dialog
		}

		String state = selected ? "selected" : "de-selected";
		waitForCondition(() -> c.isSelected() == selected || !c.isShowing(),
			"Timed-out waiting for component to become " + state + ": " +
				c.getClass().getSimpleName());
	}

	// Finds a button within the container or its sub-components that has the specified text
	// within the text of the button.
	protected AbstractButton findButton(Container container, String text) {
		Component[] comp = container.getComponents();
		if (!container.isShowing()) {
			// this component uses hidden panels via a CardLayout--ignore hidden panels, 
			// as they are for different conflicts
			return null;
		}

		for (Component element : comp) {
			if ((element instanceof AbstractButton && element.isShowing()) &&
				((AbstractButton) element).getText().indexOf(text) >= 0) {
				return (AbstractButton) element;
			}
			else if ((element instanceof Container) && element.isShowing()) {
				AbstractButton b = findButton((Container) element, text);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}

	protected void waitForCompletion() throws Exception {
		waitForMergeCompletion();
	}

	protected void checkConflictCount(int expectedCount) {
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		ArrayList<DataType> list = new ArrayList<>();
		dtm.findDataTypes("*.conflict*", list, false, null);
		assertEquals(expectedCount, list.size());
	}

	protected void executeDummyMerge() throws Exception {
		originalProgram = mtf.getOriginalProgram();
		myProgram = mtf.getPrivateProgram();// my program
		resultProgram = mtf.getResultProgram();// destination program
		latestProgram = mtf.getLatestProgram();// latest version (results and latest start out the same);

		ProgramChangeSet resultChangeSet = mtf.getResultChangeSet();
		ProgramChangeSet myChangeSet = mtf.getPrivateChangeSet();
		mergeMgr = new DummyMergeManager(resultProgram, myProgram, originalProgram, latestProgram,
			resultChangeSet, myChangeSet);
		dataTypeMergeMgr = new DataTypeMergeManager(mergeMgr, resultProgram, myProgram,
			originalProgram, latestProgram, resultChangeSet, myChangeSet);
		Thread t = new Thread(() -> {
			try {
				mergeMgr.merge();
			}
			catch (CancelledException e) {
				// User cancelled.
			}
		});
		t.start();

		waitForMergeTool();
		assertNotNull(mergeTool);
	}

	protected void resolveCategoryConflict(final int option, boolean useForAll,
			String expectedCategoryPath) throws Exception {

		waitForPrompting();

		CategoryMergePanel mergePanel = getMergePanel(CategoryMergePanel.class);
		assertNotNull(mergePanel);

		CategoryConflictPanel conflictPanel = getMergePanel(CategoryConflictPanel.class);
		assertNotNull(conflictPanel);

		JLabel categoryLabel = (JLabel) getInstanceField("categoryLabel", conflictPanel);
		String actualCategoryText = categoryLabel.getText();
		assertEquals(expectedCategoryPath, actualCategoryText);

		resolveConflict(CategoryMergePanel.class, CategoryConflictPanel.class, option, useForAll);
	}

	protected <S extends Container, T extends Container> void resolveConflict(
			final Class<S> mergePanelClass, final Class<T> conflictPanelClass, final int option,
			boolean useForAll) throws Exception {
		waitForPrompting();

		S b = getMergePanel(mergePanelClass);
		S mergePanel = mergePanelClass.cast(b);
		assertNotNull(mergePanel);

		T c = getMergePanel(conflictPanelClass);
		T conflictPanel = conflictPanelClass.cast(c);
		assertNotNull(conflictPanel);

		switch (option) {
			case DataTypeMergeManager.OPTION_LATEST:
				JRadioButton latestRB = (JRadioButton) getInstanceField("latestRB", conflictPanel);
				assertNotNull(latestRB);
				if (!latestRB.isSelected()) {
					pressButton(latestRB);
				}
				break;
			case DataTypeMergeManager.OPTION_MY:
				JRadioButton myRB = (JRadioButton) getInstanceField("myRB", conflictPanel);
				assertNotNull(myRB);
				if (!myRB.isSelected()) {
					pressButton(myRB);
				}
				break;
			case DataTypeMergeManager.OPTION_ORIGINAL:
				JRadioButton origRB = (JRadioButton) getInstanceField("originalRB", conflictPanel);
				assertNotNull(origRB);
				if (!origRB.isSelected()) {
					pressButton(origRB);
				}
				break;
			default:
				throw new IllegalArgumentException(option + " is not a valid conflict option.");
		}

		JCheckBox useForAllCB = (JCheckBox) getInstanceField("useForAllCB", mergePanel);
		assertNotNull(useForAllCB);
		useForAllCB.setSelected(useForAll);

		waitForApply(true);
		chooseApply();
	}

}
