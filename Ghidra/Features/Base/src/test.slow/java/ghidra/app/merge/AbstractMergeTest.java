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
package ghidra.app.merge;

import static org.junit.Assert.*;

import java.awt.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JFrame;

import org.junit.*;

import docking.DockingWindowManager;
import generic.util.WindowUtilities;
import ghidra.framework.model.Transaction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.MergeTestFacilitator;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;

public abstract class AbstractMergeTest extends AbstractGhidraHeadedIntegrationTest {

	// TODO this may need to be modified for parallel mode
	protected static final int MAX_MERGE_TIMEOUT = 20000;

	protected MergeTestFacilitator mtf;
	protected Program originalProgram;
	protected Program myProgram;
	protected Program resultProgram;
	protected Program latestProgram;
	protected PluginTool mergeTool;
	protected ProgramMultiUserMergeManager mergeMgr;

	@Before
	public void setUp() throws Exception {
		mtf = new MergeTestFacilitator();
		fixupGUI();
		TestEnv testEnv = mtf.getTestEnvironment();
		testEnv.getTool().setToolName("TestTool");
	}

	@After
	public void tearDown() throws Exception {

		bringDownMergeTool();
		checkTransactions();// Shouldn't have any transactions. If so, note them
		mtf.dispose();
	}

	private void bringDownMergeTool() {

		if (resultProgram != null) {
			resultProgram.flushEvents();
		}

		waitForSwing();

		if (mergeMgr == null) {
			return; // nothing to dispose
		}

		try {
			// Cancel the merge if its window is still around			
			if (!mergeMgr.processingCompleted()) {
				Msg.debug(this, "Uh-Oh  Still processing in TearDown() ...");
				printOpenWindows();
				tryToPressCancel();
			}

			// Wait momentarily if the merge still hasn't finished processing
			waitForConditionWithoutFailing(() -> mergeMgr.processingCompleted());
		}
		catch (Exception e) {
			Msg.error(this, "Exception disposing", e);
		}

		// If the tool is still visible, get rid of it.
		if (mergeTool != null && mergeTool.isVisible()) {
			runSwing(() -> mergeTool.setVisible(false));
			waitForSwing();
		}
	}

	private void tryToPressCancel() {
		Window window = DockingWindowManager.getActiveInstance().getActiveWindow();
		JButton cancel = findButtonByText(window, "Cancel");
		if (cancel == null) {
			Msg.debug(this, "No cancel button found");
			return;
		}

		pressButton(cancel, false);
		waitForSwing();

		Window cancelWindow = waitForValueWithoutFailing(() -> getWindow("Confirm Cancel Merge"));
		if (cancelWindow != null) {
			pressButtonByText(cancelWindow, "Yes", false);
			waitForSwing();
		}
		else {
			Msg.debug(this, "Could not find cancel window in tearDown()");
		}
	}

	protected long sleep() {
		return sleep(DEFAULT_WAIT_DELAY);
	}

	protected void waitForMergeCompletion() {
		int totalTime = 0;
		while (mergeMgr != null && !mergeMgr.processingCompleted()) {

			Window win = getWindowByTitleContaining(null, "Merge Information");
			if (win != null) {
				try {
					pressButtonByText(win, "OK");
				}
				catch (AssertionError e) {
					// If we can't press an OK button,then just continue.
				}
			}

			totalTime += sleep();

			if (totalTime >= MAX_MERGE_TIMEOUT) {

				List<Dialog> modals =
					WindowUtilities.getOpenModalDialogsFor(mergeMgr.getMergeTool().getToolFrame());
				Msg.debug(this, "Open modal dialogs: ");
				for (Dialog dialog : modals) {
					capture(dialog);
				}

				String trace = createStackTraceForAllThreads();
				Assert.fail("Merge Tool is unexpectedly still not completed after timeout (ms): " +
					MAX_MERGE_TIMEOUT + "\nThread Traces:\n" + trace);
			}
		}
	}

	private void capture(Dialog dialog) {
		String title = WindowUtilities.getTitle(dialog);
		String name = title.replaceAll("\\W", "_");
		try {
			Image image = createScreenImage(dialog);
			writeImage(image, "modal.dialog." + name);
		}
		catch (Exception e) {
			Msg.error(this, "Unable to capture dialog: " + dialog);
		}
	}

	/* 
	 * Prints out any transactions that are still in progress.
	 */
	protected void checkTransactions() {
		checkTransactions("");
	}

	/* 
	 * Prints out any transactions that are still in progress.
	 */
	protected void checkTransactions(String prefix) {
		Program p = mtf.getResultProgram();
		if (p == null) {
			return;
		}

		Transaction tx = p.getCurrentTransaction();
		if (tx == null) {
			return;
		}
		ArrayList<String> list = tx.getOpenSubTransactions();
		StringBuffer tip = new StringBuffer();
		Iterator<String> iter = list.iterator();
		while (iter.hasNext()) {
			if (tip.length() != 0) {
				tip.append('\n');
			}
			tip.append(iter.next());
		}
		Msg.error(this, prefix + "Test Case " + testName.getMethodName() +
			" : ERROR: Transactions still exist!  " + tip.toString());
	}

	protected <T extends Component> T getMergePanel(Class<T> desiredClass) {

		if (mergeTool == null) {
			return null;
		}

		JFrame toolFrame = mergeTool.getToolFrame();
		if (toolFrame == null) {
			return null;
		}

		T c = findComponent(toolFrame, desiredClass, true);
		long total = 0;
		while (c == null) {

			total += sleep();
			if (total >= MAX_MERGE_TIMEOUT) {
				fail("Timed-out waiting for merge panel - " + MAX_MERGE_TIMEOUT + " ms: " +
					desiredClass);
			}

			c = findComponent(toolFrame, desiredClass, true);
		}

		return desiredClass.cast(c);
	}

	/**
	 * Call this after executeMerge() if you expect to get a prompt from one of the merge
	 * manager's "choose" dialogs. It will give the initial automerge a chance to occur
	 * before you begin trying to programmatically choose buttons.
	 * This currently waits up to 5 seconds for prompting to begin.
	 */
	protected void waitForPrompting() {
		waitForPrompting(MAX_MERGE_TIMEOUT);
	}

	protected void waitForPrompting(int timeoutMS) {
		int total = 0;
		while (!mergeMgr.isPromptingUser()) {

			total += sleep();
			if (total >= timeoutMS) {
				Assert.fail("Failed waiting for Prompting to start");
			}
		}
	}

	protected void waitForApply(boolean enabled) throws Exception {
		MergeManagerPlugin mergePlugin =
			(MergeManagerPlugin) getInstanceField("mergePlugin", mergeMgr);
		assertNotNull(mergePlugin);
		Object mergeManagerProvider = getInstanceField("provider", mergePlugin);
		assertNotNull(mergeManagerProvider);
		JButton applyButton = (JButton) getInstanceField("applyButton", mergeManagerProvider);
		assertNotNull(applyButton);

		waitForCondition(() -> applyButton.isEnabled() == enabled,
			"Failed waiting for Apply to be " + (enabled ? "enabled." : "disabled."));
	}

	protected void waitForMergeTool() {
		int total = 0;
		while (mergeTool == null) {
			total += sleep();
			mergeTool = mergeMgr.getMergeTool();

			if (total >= MAX_MERGE_TIMEOUT) {
				Assert.fail("Failed waiting for Prompting to start");
			}
		}
	}

	protected void chooseApply() throws Exception {

		MergeManagerPlugin mergePlugin =
			(MergeManagerPlugin) getInstanceField("mergePlugin", mergeMgr);
		assertNotNull(mergePlugin);
		Object mergeManagerProvider = getInstanceField("provider", mergePlugin);
		assertNotNull(mergeManagerProvider);
		JButton applyButton = (JButton) getInstanceField("applyButton", mergeManagerProvider);
		assertNotNull(applyButton);
		pressButton(applyButton);
	}

}
