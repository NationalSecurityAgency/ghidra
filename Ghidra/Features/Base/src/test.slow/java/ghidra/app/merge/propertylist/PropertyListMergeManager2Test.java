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
package ghidra.app.merge.propertylist;

import static org.junit.Assert.*;

import java.awt.*;
import java.util.Date;
import java.util.Set;

import javax.swing.*;

import org.junit.Test;

import generic.util.WindowUtilities;
import ghidra.app.merge.*;
import ghidra.framework.options.Options;
import ghidra.program.database.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Tests for the conflict panel in the property list merge manager.
 *
 *
 */

public class PropertyListMergeManager2Test extends AbstractMergeTest {

	private Window window;
	private Date currentDate;

	@Test
	public void testTypeMismatchAskTheUserOpt1() throws Exception {
		// test case 9: types do not match for the same property name
		//              "int" in the latest version,
		//              "string" in the private version
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setInt("Background", 5);

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Green");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		merge();

		selectButtonAndApply(MergeConstants.LATEST_TITLE);

		Options list = resultProgram.getOptions("Colors");
		assertEquals(5, list.getInt("Background", 0));
	}

	@Test
	public void testTypeMismatchAskTheUserOpt2() throws Exception {
		// test case 9: types do not match for the same property name
		//              "int" in the latest version,
		//              "string" in the private version
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setInt("Background", 5);

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Green");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		merge();
		selectButtonAndApply(MergeConstants.MY_TITLE);

		Options list = resultProgram.getOptions("Colors");
		assertEquals("Green", list.getString("Background", (String) null));
	}

	@Test
	public void testTypeMismatchAskTheUserOpt3() throws Exception {
		// test case 9: types do not match for the same property name
		//              "int" in the latest version,
		//              "string" in the private version
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setInt("Background", 5);

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Green");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		merge();
		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE);

		Options list = resultProgram.getOptions("Colors");
		assertTrue(!list.contains("Background"));
	}

	@Test
	public void testValuesChangedAskTheUserOpt1() throws Exception {
		// test case #6: conflict because both values changed
		// Choose 'latest'
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Blue");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Green");

				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge();
		selectButtonAndApply(MergeConstants.LATEST_TITLE);
		Options list = resultProgram.getOptions("Colors");
		assertEquals("Blue", list.getString("Background", (String) null));
	}

	@Test
	public void testValuesChangedAskTheUserOpt2() throws Exception {
		// test case #6: conflict because both values changed
		// Choose 'checked out' option
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Blue");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Green");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		merge();
		selectButtonAndApply(MergeConstants.MY_TITLE);

		Options list = resultProgram.getOptions("Colors");
		assertEquals("Green", list.getString("Background", (String) null));
	}

	@Test
	public void testValuesChangedAskTheUserOpt3() throws Exception {
		// test case #6: conflict because both values changed
		// Choose 'original' option
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Blue");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Green");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		merge();
		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE);

		Options list = resultProgram.getOptions("Colors");
		assertTrue(!list.contains("Background"));
	}

	@Test
	public void testMultipleConflicts() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Blue");
					list = program.getOptions("Program Information");
					list.setString("Executable Format", "some undetermined format");

					list = program.getOptions(Program.ANALYSIS_PROPERTIES);
					list.removeOption("Options.Mark Bad Disassembly");
					list = program.getOptions("Analysis");
					list.setBoolean("Options.Mark Bad Disassembly", true);
				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Green");
					list = program.getOptions("Program Information");
					list.setString("Executable Format", "my format");

					list = program.getOptions("Analysis");
					list.setBoolean("Options.Mark Bad Disassembly", false);

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		merge();
		selectButtonAndApply(MergeConstants.MY_TITLE, false);// my for Analysis
		selectButtonAndApply(MergeConstants.LATEST_TITLE, false);// lastest for Colors
		selectButtonAndApply(MergeConstants.MY_TITLE);// my for Program Information

		Options list = resultProgram.getOptions("Colors");
		assertEquals("Blue", list.getString("Background", (String) null));

		list = resultProgram.getOptions("Program Information");
		assertEquals("my format", list.getString("Executable Format", (String) null));

		list = resultProgram.getOptions("Analysis");
		assertTrue(list.contains("Options.Mark Bad Disassembly"));
		assertTrue(!list.getBoolean("Options.Mark Bad Disassembly", false));
	}

	@Test
	public void testDateConflicts() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setDate("TimeOfUpdate", new Date(System.currentTimeMillis() - 50000L));
				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					currentDate = new Date(System.currentTimeMillis());
					list.setDate("TimeOfUpdate", currentDate);

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		merge();
		selectButtonAndApply(MergeConstants.MY_TITLE, false);

		Options list = resultProgram.getOptions("Colors");

		assertEquals(currentDate, list.getDate("TimeOfUpdate", (Date) null));
	}

	@Test
	public void testDateDeletedConflicts() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setDate("TimeOfUpdate", new Date(System.currentTimeMillis() - 50000L));
				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					currentDate = new Date(System.currentTimeMillis());
					list.setDate("TimeOfUpdate", currentDate);

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		merge();
		selectButtonAndApply(MergeConstants.MY_TITLE, false);

		Options list = resultProgram.getOptions("Colors");

		assertEquals(currentDate, list.getDate("TimeOfUpdate", (Date) null));
	}

	@Test
	public void testAnalyzedTrueInLatest() throws Exception {
		// test case: conflict because both values changed
		// Choose 'latest'
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", true);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// no-op
			}
		});

		merge(false);
		waitForCompletion();
		Options list = resultProgram.getOptions("Program Information");
		assertEquals(true, list.contains("Analyzed"));
		assertEquals(true, list.getBoolean("Analyzed", false));
	}

	@Test
	public void testAnalyzedFalseInLatest() throws Exception {
		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", false);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", false);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Green");

				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge(false);
		waitForCompletion();
		Options list = resultProgram.getOptions("Program Information");
		assertEquals(true, list.contains("Analyzed"));
		assertEquals(false, list.getBoolean("Analyzed", false));
	}

	@Test
	public void testAnalyzedTrueInMy() throws Exception {
		// test case: conflict because both values changed
		// Choose 'latest'
		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// no-op
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", true);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge(false);
		waitForCompletion();
		Options list = resultProgram.getOptions("Program Information");
		assertEquals(true, list.contains("Analyzed"));
		assertEquals(true, list.getBoolean("Analyzed", false));
	}

	@Test
	public void testAnalyzedFalseInMy() throws Exception {
		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", false);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				// no-op
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", false);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge(false);
		waitForCompletion();
		Options list = resultProgram.getOptions("Program Information");
		assertEquals(true, list.contains("Analyzed"));
		assertEquals(false, list.getBoolean("Analyzed", false));
	}

	@Test
	public void testAnalyzedTrueInBoth() throws Exception {
		// test case: conflict because both values changed
		// Choose 'latest'
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", true);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", true);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge(false);
		waitForCompletion();
		Options list = resultProgram.getOptions("Program Information");
		assertEquals(true, list.contains("Analyzed"));
		assertEquals(true, list.getBoolean("Analyzed", false));
	}

	@Test
	public void testAnalyzedFalseInBoth() throws Exception {
		// test case: conflict because both values changed
		// Choose 'latest'
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", false);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", false);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge(false);
		waitForCompletion();
		Options list = resultProgram.getOptions("Program Information");
		assertEquals(true, list.contains("Analyzed"));
		assertEquals(false, list.getBoolean("Analyzed", false));
	}

	@Test
	public void testAnalyzedTrueInLatestFalseInMy() throws Exception {
		// test case: conflict because both values changed
		// Choose 'latest'
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", true);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", false);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge(false);
		waitForCompletion();
		Options list = resultProgram.getOptions("Program Information");
		assertEquals(true, list.contains("Analyzed"));
		assertEquals(true, list.getBoolean("Analyzed", false));
	}

	@Test
	public void testAnalyzedFalseInLatestTrueInMy() throws Exception {
		// test case: conflict because both values changed
		// Choose 'latest'
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", false);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setBoolean("Analyzed", true);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge(false);
		waitForCompletion();
		Options list = resultProgram.getOptions("Program Information");
		assertEquals(true, list.contains("Analyzed"));
		assertEquals(true, list.getBoolean("Analyzed", false));
	}

	private void merge() throws Exception {
		merge(true);
	}

	private void merge(boolean waitForConflict) throws Exception {
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
				// can't happen
			}
		});
		t.start();
		waitForSwing();

		if (!waitForConflict) {
			return;
		}

		PropertyListMergePanel mergePanel = waitForValue(() -> {

			PropertyListMergePanel panel = findComponent(PropertyListMergePanel.class);
			if (panel == null) {
				return null;
			}
			if (!panel.isShowing()) {
				return null;
			}
			return panel;

		}); //, MAX_MERGE_TIMEOUT); TODO a reminder to see if we need a larger timeout mechanism

		window = WindowUtilities.windowForComponent(mergePanel);
		assertNotNull("Could not find active window", window);
		assertTrue(window.isShowing());
	}

	private <T extends Component> T findComponent(Class<T> desiredClass) {

		Set<Window> allWindows = getAllWindows();
		for (Window w : allWindows) {
			if (!w.isShowing()) {
				continue;
			}
			T t = findComponent(w, desiredClass, true);
			if (t != null) {
				return t;
			}
		}
		return null;
	}

	private void waitForCompletion() throws Exception {
		waitForMergeCompletion();
	}

	private void selectButtonAndApply(String text, boolean doWait) throws Exception {
		JRadioButton rb = (JRadioButton) findButton(window, text);
		if (rb == null) {

			String title = getTitleForWindow(window);
			Msg.debug(this, "Active Window: " + title + "\nAll open windows:\n");

			printOpenWindows();

			// 12/87/20 -  put in to find intermittent test failure when the button cannot be found
			capture(window, "missing.button." + text);

			fail("Unable to find radio button '" + text + "'; see console for details");
		}

		assertNotNull(rb);
		SwingUtilities.invokeAndWait(() -> rb.setSelected(true));
		JButton applyButton = findButtonByText(window, "Apply");
		assertNotNull(applyButton);

		pressButton(applyButton);
		waitForSwing();
		resultProgram.flushEvents();
		if (doWait) {
			waitForCompletion();
		}
		else {
			// wait until the panel has been reset			
			waitForCondition(() -> !applyButton.isEnabled() || !rb.isVisible());
		}

	}

	private void selectButtonAndApply(String text) throws Exception {
		selectButtonAndApply(text, true);
	}

	private AbstractButton findButton(Container container, String text) {

		// note: there may be some timing issue with accessing swing components from the test
		//       thread.   This waitForSwing() will cause registers to get flushed, making swing
		//       changes visible to this thread.  
		//
		//       The correct change would probably be to put this code and the similar code from 
		//       the test framework onto the swing thread when attempting to find swing widgets.
		waitForSwing();
		Component[] comp = container.getComponents();
		for (Component element : comp) {
			if ((element instanceof AbstractButton && element.isVisible()) &&
				((AbstractButton) element).getText().indexOf(text) >= 0) {
				return (AbstractButton) element;
			}
			else if ((element instanceof Container) && element.isVisible()) {
				AbstractButton b = findButton((Container) element, text);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}

}
