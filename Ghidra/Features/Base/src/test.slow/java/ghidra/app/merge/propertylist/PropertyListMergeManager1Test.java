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

import javax.swing.*;

import org.junit.Test;

import ghidra.app.merge.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PropertyListMergeManager1Test extends AbstractMergeTest {

	private ProgramMultiUserMergeManager multiUserMergeManager;

	@Test
	public void testAddNewProperty() throws Exception {
		// test case #2: property list does not exist in latest version;
		//               list was added to private version
		// test case #3: property name does not exist in latest version,
		//               but was added to private version
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes to Latest.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Colors");
					list.setString("Background", "Blue");
					list.setString("Foreground", "Yellow");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		executeMerge();

		Options list = resultProgram.getOptions("Colors");
		assertEquals(2, list.getOptionNames().size());

		assertEquals("Blue", list.getString("Background", "green"));
		assertEquals("Yellow", list.getString("Foreground", "green"));
	}

	@Test
	public void testPropertyDeleted() throws Exception {
		// test case #4: Property name exists, no value changed in latest version;
		//               property name was deleted in private version	
		//			     (was in the original)

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes to Latest.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Functions");
					list.removeOption("Stack Analysis");
				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});
		executeMerge();
		Options list = resultProgram.getOptions("Functions");
		assertTrue(!list.contains("Stack Analysis"));
	}

	@Test
	public void testPropertyChangedAndDeleted() throws Exception {
		// test case #5: Property value changed in the latest version;
		//               property was deleted in the private version
		//               (was in the original)

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Data");
					list.setInt("Create Address Tables.Minimum Table Size", 5);

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
					Options list = program.getOptions("Data");
					list.removeOption("Create Address Tables.Minimum Table Size");
				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});
		executeMerge();
		Options list = resultProgram.getOptions("Data");
		assertTrue(list.contains("Create Address Tables.Minimum Table Size"));
		assertEquals(5, list.getInt("Create Address Tables.Minimum Table Size", 0));
	}

	@Test
	public void testPropertyChangedAndDeleted2() throws Exception {
		// test case #5A: Property value changed in the latest version;
		//                property was deleted in the private version, but
		//                was not in the original
		mtf.initialize("notepad", new ProgramModifierListener() {
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
					list.removeOption("Background");
				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});
		executeMerge(-1);// not a conflict
		Options list = resultProgram.getOptions("Colors");
		assertEquals("Blue", list.getString("Background", (String) null));
	}

	@Test
	public void testAddedValuesChanged() throws Exception {
		// test case #6: conflict because both values changed
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

		executeMerge(PropertyListMergeManager.MY_VERSION);
		Options list = resultProgram.getOptions("Colors");
		assertEquals("Green", list.getString("Background", (String) null));
	}

	@Test
	public void testValuesChanged() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setString("Executable Format", "some undetermined format");

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
					list.setString("Executable Format", "my format");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		executeMerge(PropertyListMergeManager.MY_VERSION);
		Options list = resultProgram.getOptions("Program Information");
		assertEquals("my format", list.getString("Executable Format", (String) null));
	}

	@Test
	public void testValuesChanged2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Program Information");
					list.setString("Executable Format", "some undetermined format");

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
					list.setString("Executable Format", "my format");

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		executeMerge(PropertyListMergeManager.ORIGINAL_VERSION);
		Options list = resultProgram.getOptions("Program Information");
		assertEquals("unknown", list.getString("Executable Format", (String) null));
	}

	@Test
	public void testMyValueChanged() throws Exception {
		// test case #7: no change to the latest version, 
		//               value changed in the private version

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes to Latest.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options list = program.getOptions("Functions");
					list.setBoolean("Stack Analysis", false);

				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});
		executeMerge();
		Options list = resultProgram.getOptions("Functions");
		assertTrue(!list.getBoolean("Stack Analysis", true));
	}

	@Test
	public void testNoChange() throws Exception {
		// test case #8: value changed in the latest version,
		//               no change in private version	
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
				// No changes to My.
			}
		});
		executeMerge();
		Options list = resultProgram.getOptions("Colors");
		assertEquals("Blue", list.getString("Background", (String) null));
	}

	@Test
	public void testDoNotUseForAll() throws Exception {

		setupUseForAllTest();

		merge();
		selectButtonAndUseForAllThenApply("value = \'Blue\' (Latest)", false);// Background Color
		selectButtonAndUseForAllThenApply("value = \'Yellow\' (Latest)", false);// Foreground Color
		selectButtonAndUseForAllThenApply("value = \'7\' (Checked Out)", false);// Minimum Table Size
		selectButtonAndUseForAllThenApply("value = \'unknown\' (Original)", false);// Executable Format
		waitForCompletion();

		Options infoList = resultProgram.getOptions("Program Information");
		assertEquals("unknown", infoList.getString("Executable Format", (String) null));

		Options colorsList = resultProgram.getOptions("Colors");
		assertEquals(2, colorsList.getOptionNames().size());
		assertEquals("Blue", colorsList.getString("Background", "Blue"));
		assertEquals("Yellow", colorsList.getString("Foreground", "Maroon"));

		Options dataList = resultProgram.getOptions("Data");
		assertTrue(dataList.contains("Create Address Tables.Minimum Table Size"));
		assertEquals(7, dataList.getInt("Create Address Tables.Minimum Table Size", 0));
	}

	private void setupUseForAllTest() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Options infoList = program.getOptions("Program Information");
					infoList.setString("Executable Format", "some undetermined format");
					Options colorsList = program.getOptions("Colors");
					colorsList.setString("Background", "Blue");
					colorsList.setString("Foreground", "Yellow");
					Options dataList = program.getOptions("Data");
					dataList.setInt("Create Address Tables.Minimum Table Size", 5);
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
					list.setString("Executable Format", "my format");
					Options colorsList = program.getOptions("Colors");
					colorsList.setString("Background", "Grey");
					colorsList.setString("Foreground", "Maroon");
					Options dataList = program.getOptions("Data");
					dataList.setInt("Create Address Tables.Minimum Table Size", 7);
				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});
	}

	@Test
	public void testUseForAllPickLatest() throws Exception {

		setupUseForAllTest();

		merge();
		selectButtonAndUseForAllThenApply("value = \'Blue\' (Latest)", true);// Background Color
//		selectButtonAndUseForAllThenApply("value = \'Yellow\' (Latest)", false); // Foreground Color
//		selectButtonAndUseForAllThenApply("value = \'5\' (Latest)", false); // Minimum Table Size
//		selectButtonAndUseForAllThenApply("value = \'unknown\' (Latest)", false); // Executable Format
		waitForCompletion();

		Options infoList = resultProgram.getOptions("Program Information");
		assertEquals("some undetermined format",
			infoList.getString("Executable Format", (String) null));

		Options colorsList = resultProgram.getOptions("Colors");
		assertEquals(2, colorsList.getOptionNames().size());
		assertEquals("Blue", colorsList.getString("Background", "Blue"));
		assertEquals("Yellow", colorsList.getString("Foreground", "Maroon"));

		Options dataList = resultProgram.getOptions("Data");
		assertTrue(dataList.contains("Create Address Tables.Minimum Table Size"));
		assertEquals(5, dataList.getInt("Create Address Tables.Minimum Table Size", 0));
	}

	@Test
	public void testUseForAllPickMy() throws Exception {

		setupUseForAllTest();

		merge();
		selectButtonAndUseForAllThenApply("value = \'Grey\' (Checked Out)", true);// Background Color
//		selectButtonAndUseForAllThenApply("value = \'Maroon\' (Checked Out)", false); // Foreground Color
//		selectButtonAndUseForAllThenApply("value = \'7\' (Checked out)", false); // Minimum Table Size
//		selectButtonAndUseForAllThenApply("value = \'my format\' (Checked out)", false); // Executable Format
		waitForCompletion();

		Options infoList = resultProgram.getOptions("Program Information");
		assertEquals("my format", infoList.getString("Executable Format", (String) null));

		Options colorsList = resultProgram.getOptions("Colors");
		assertEquals(2, colorsList.getOptionNames().size());
		assertEquals("Grey", colorsList.getString("Background", "Blue"));
		assertEquals("Maroon", colorsList.getString("Foreground", "Yellow"));

		Options dataList = resultProgram.getOptions("Data");
		assertTrue(dataList.contains("Create Address Tables.Minimum Table Size"));
		assertEquals(7, dataList.getInt("Create Address Tables.Minimum Table Size", 0));
	}

	@Test
	public void testUseForAllPickOriginal() throws Exception {

		setupUseForAllTest();

		merge();
		selectButtonAndUseForAllThenApply("Value deleted (Original)", true);// Background Color
//		selectButtonAndUseForAllThenApply("Value deleted (Original)", false); // Foreground Color
//		selectButtonAndUseForAllThenApply("Value deleted (Original)", false); // Minimum Table Size
//		selectButtonAndUseForAllThenApply("Value deleted (Original)", false); // Executable Format
		waitForCompletion();

		Options infoList = resultProgram.getOptions("Program Information");
		assertEquals("unknown", infoList.getString("Executable Format", (String) null));

		Options colorsList = resultProgram.getOptions("Colors");
		assertEquals(0, colorsList.getOptionNames().size());

		Options dataList = resultProgram.getOptions("Data");
		assertFalse(dataList.contains("Create Address Tables.Minimum Table Size"));
	}

	////////////////////////////

	private void executeMerge() {
		executeMerge(-1);
	}

	private void executeMerge(int option) {
		originalProgram = mtf.getOriginalProgram();
		myProgram = mtf.getPrivateProgram();// my program
		resultProgram = mtf.getResultProgram();// destination program
		latestProgram = mtf.getLatestProgram();// latest version (results and latest start out the same);

		ProgramChangeSet resultChangeSet = mtf.getResultChangeSet();
		ProgramChangeSet myChangeSet = mtf.getPrivateChangeSet();
		ProgramMultiUserMergeManager dummyMergeManager = new DummyMergeManager(resultProgram,
			myProgram, originalProgram, latestProgram, resultChangeSet, myChangeSet);
		PropertyListMergeManager merger = new PropertyListMergeManager(dummyMergeManager,
			resultProgram, myProgram, originalProgram, latestProgram);
		if (option >= 0) {
			merger.setConflictResolution(option);
		}
		merger.merge(TaskMonitor.DUMMY);
	}

	private void merge() throws Exception {
		originalProgram = mtf.getOriginalProgram();
		myProgram = mtf.getPrivateProgram();// my program
		resultProgram = mtf.getResultProgram();// destination program
		latestProgram = mtf.getLatestProgram();// latest version (results and latest start out the same);

		ProgramChangeSet resultChangeSet = mtf.getResultChangeSet();
		ProgramChangeSet myChangeSet = mtf.getPrivateChangeSet();

		multiUserMergeManager = new ProgramMultiUserMergeManager(resultProgram, myProgram,
			originalProgram, latestProgram, resultChangeSet, myChangeSet);
		Thread t = new Thread(() -> {
			try {
				multiUserMergeManager.merge();
			}
			catch (CancelledException e) {
				// User cancelled.
			}
		});
		t.start();
		waitForPostedSwingRunnables();
	}

	private PluginTool getMergeTool() {
		if (mergeTool == null) {
			int sleepyTime = 50;
			int total = 0;
			while (mergeTool == null && total < 100) {
				mergeTool = multiUserMergeManager.getMergeTool();
				sleep(sleepyTime);
			}
		}

		if (mergeTool == null) {
			throw new AssertException("Unable to find merge tool!");
		}

		return mergeTool;
	}

	private void waitForCompletion() throws Exception {
		waitForMergeCompletion();
	}

	private void selectButtonAndUseForAllThenApply(String partialButtonText,
			final boolean useForAll) throws Exception {

		int count = 0;
		ConflictPanel panel = null;
		PluginTool tool = getMergeTool();
		while (panel == null && count < 100) {
			panel = findComponent(tool.getToolFrame(), ConflictPanel.class, true);
			Thread.sleep(50);
			++count;
		}
		assertNotNull(panel);

		final JCheckBox useForAllCB = (JCheckBox) getInstanceField("useForAllCB", panel);
		assertNotNull(useForAllCB);
		final JRadioButton rb = (JRadioButton) findButton(panel, partialButtonText);
		assertNotNull(rb);
		SwingUtilities.invokeAndWait(() -> {
			rb.setSelected(true);
			useForAllCB.setSelected(useForAll);
		});
		Window window = windowForComponent(panel);
		JButton applyButton = findButtonByText(window, "Apply");
		assertNotNull(applyButton);

		pressButton(applyButton);
		waitForPostedSwingRunnables();
		resultProgram.flushEvents();
		// wait until the panel has been reset
		while (applyButton.isEnabled() && rb.isVisible()) {
			Thread.sleep(250);
		}
	}

	private AbstractButton findButton(Container container, String partialButtonText) {
		Component[] comp = container.getComponents();
		for (Component element : comp) {
			if ((element instanceof AbstractButton && element.isVisible()) &&
				((AbstractButton) element).getText().indexOf(partialButtonText) >= 0) {
				return (AbstractButton) element;
			}
			else if ((element instanceof Container) && element.isVisible()) {
				AbstractButton b = findButton((Container) element, partialButtonText);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}
}
