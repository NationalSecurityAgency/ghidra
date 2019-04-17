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
package ghidra.app.merge.tree;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.awt.Container;

import javax.swing.*;

import ghidra.app.merge.*;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public abstract class AbstractProgramTreeMergeManagerTest extends AbstractMergeTest {

	protected int mainTreeCount;
	protected int treeThreeCount;

	protected void executeMerge() throws Exception {
		executeMerge(-1);
	}

	protected void executeMerge(int option) throws Exception {
		originalProgram = mtf.getOriginalProgram();
		myProgram = mtf.getPrivateProgram();// my program
		resultProgram = mtf.getResultProgram();// destination program
		latestProgram = mtf.getLatestProgram();// latest version (results and latest start out the same);

		ProgramChangeSet resultChangeSet = mtf.getResultChangeSet();
		ProgramChangeSet myChangeSet = mtf.getPrivateChangeSet();
		ProgramMultiUserMergeManager dummyMergeManager = new DummyMergeManager(resultProgram,
			myProgram, originalProgram, latestProgram, resultChangeSet, myChangeSet);
		ProgramTreeMergeManager programTreeMergeManager =
			new ProgramTreeMergeManager(dummyMergeManager, resultProgram, myProgram,
				originalProgram, latestProgram, resultChangeSet, myChangeSet);
		if (option >= 0) {
			programTreeMergeManager.setConflictResolution(option);
		}
		programTreeMergeManager.merge(TaskMonitorAdapter.DUMMY_MONITOR);
	}

	protected void merge() throws Exception {
		originalProgram = mtf.getOriginalProgram();
		myProgram = mtf.getPrivateProgram();// my program
		resultProgram = mtf.getResultProgram();// destination program
		latestProgram = mtf.getLatestProgram();// latest version (results and latest start out the same);

		ProgramChangeSet resultChangeSet = mtf.getResultChangeSet();
		ProgramChangeSet myChangeSet = mtf.getPrivateChangeSet();

		mergeMgr = new ProgramMultiUserMergeManager(resultProgram, myProgram, originalProgram,
			latestProgram, resultChangeSet, myChangeSet);
		Thread t = new Thread(() -> {
			try {
				mergeMgr.merge();
			}
			catch (CancelledException e) {
				// User cancelled.
			}
		});
		t.start();
		waitForSwing();
	}

	protected void pressApply() throws Exception {
		MergeManagerPlugin mergePlugin =
			(MergeManagerPlugin) getInstanceField("mergePlugin", mergeMgr);
		assertNotNull(mergePlugin);
		Object mergeManagerProvider = getInstanceField("provider", mergePlugin);
		assertNotNull(mergeManagerProvider);
		JButton applyButton = (JButton) getInstanceField("applyButton", mergeManagerProvider);
		assertNotNull(applyButton);
		pressButton(applyButton);
	}

	protected <S extends Container, T extends Container> void resolveNameConflictsPanelConflict(
			final String infoString, final int option, boolean useForAll) throws Exception {
		waitForPrompting();

		waitForMergeTool();
		NameConflictsPanel nameConflictsPanel = getMergePanel(NameConflictsPanel.class);
		assertNotNull(nameConflictsPanel);
		ProgramTreeMergePanel programTreeMergePanel = getMergePanel(ProgramTreeMergePanel.class);
		assertNotNull(programTreeMergePanel);

		// Check the info string.
		JLabel conflictsLabel = (JLabel) getInstanceField("conflictsLabel", nameConflictsPanel);
		assertEquals(infoString, conflictsLabel.getText());

		switch (option) {
			case ProgramTreeMergeManager.KEEP_OTHER_NAME:
				JRadioButton latestRB =
					(JRadioButton) getInstanceField("keepOtherRB", nameConflictsPanel);
				assertNotNull(latestRB);
				if (!latestRB.isSelected()) {
					pressButton(latestRB);
				}
				break;
			case ProgramTreeMergeManager.ADD_NEW_TREE:
				JRadioButton addOrRenameRB =
					(JRadioButton) getInstanceField("addOrRenameRB", nameConflictsPanel);
				assertNotNull(addOrRenameRB);
				if (!addOrRenameRB.isSelected()) {
					pressButton(addOrRenameRB);
				}
				break;
			case ProgramTreeMergeManager.ORIGINAL_NAME:
				JRadioButton originalRB =
					(JRadioButton) getInstanceField("originalRB", nameConflictsPanel);
				assertNotNull(originalRB);
				if (!originalRB.isSelected()) {
					pressButton(originalRB);
				}
				break;
			default:
				throw new IllegalArgumentException(option + " is not a valid conflict option.");
		}

		JCheckBox useForAllCB = (JCheckBox) getInstanceField("useForAllCB", programTreeMergePanel);
		assertNotNull(useForAllCB);
		useForAllCB.setSelected(useForAll);

		waitForSwing();

		waitForApply(true);
		pressApply();
	}

	protected <S extends Container, T extends Container> void resolveNamePanelConflict(
			final String latestName, final String myName, final int option, boolean useForAll)
			throws Exception {
		waitForPrompting();

		waitForMergeTool();
		NamePanel namePanel = getMergePanel(NamePanel.class);
		assertNotNull(namePanel);
		ProgramTreeMergePanel programTreeMergePanel = getMergePanel(ProgramTreeMergePanel.class);
		assertNotNull(programTreeMergePanel);
		TreeChangePanel panelOne =
			(TreeChangePanel) getInstanceField("panelOne", programTreeMergePanel);
		assertNotNull(panelOne);
		TreeChangePanel panelTwo =
			(TreeChangePanel) getInstanceField("panelTwo", programTreeMergePanel);
		assertNotNull(panelTwo);
		JLabel treeNameLabel1 = (JLabel) getInstanceField("treeNameLabel", panelOne);
		assertNotNull(treeNameLabel1);
		JLabel treeNameLabel2 = (JLabel) getInstanceField("treeNameLabel", panelTwo);
		assertNotNull(treeNameLabel2);
		assertEquals(latestName, treeNameLabel1.getText());
		assertEquals(myName, treeNameLabel2.getText());

		switch (option) {
			case ProgramTreeMergeManager.KEEP_OTHER_NAME:
				JRadioButton latestRB = (JRadioButton) getInstanceField("keepOtherRB", namePanel);
				assertNotNull(latestRB);
				if (!latestRB.isSelected()) {
					pressButton(latestRB);
				}
				break;
			case ProgramTreeMergeManager.KEEP_PRIVATE_NAME:
				JRadioButton myRB = (JRadioButton) getInstanceField("keepMyRB", namePanel);
				assertNotNull(myRB);
				if (!myRB.isSelected()) {
					pressButton(myRB);
				}
				break;
			case ProgramTreeMergeManager.ADD_NEW_TREE:
				JRadioButton newTreeRB = (JRadioButton) getInstanceField("newTreeRB", namePanel);
				assertNotNull(newTreeRB);
				newTreeRB.setSelected(false);
				if (!newTreeRB.isSelected()) {
					pressButton(newTreeRB);
				}
				break;
			case ProgramTreeMergeManager.ORIGINAL_NAME:
				JRadioButton originalRB = (JRadioButton) getInstanceField("originalRB", namePanel);
				assertNotNull(originalRB);
				if (!originalRB.isSelected()) {
					pressButton(originalRB);
				}
				break;
			default:
				throw new IllegalArgumentException(option + " is not a valid conflict option.");
		}

		JCheckBox useForAllCB = (JCheckBox) getInstanceField("useForAllCB", programTreeMergePanel);
		assertNotNull(useForAllCB);
		useForAllCB.setSelected(useForAll);

		waitForSwing();

		waitForApply(true);
		pressApply();
	}
}
