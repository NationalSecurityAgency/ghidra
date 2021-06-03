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
package ghidra.app.merge.memory;

import static org.junit.Assert.*;

import java.awt.*;

import javax.swing.*;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.merge.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.database.*;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

public class MemoryMergeManagerTest extends AbstractMergeTest {

	@Test
	public void testNameConflict() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setName("LatestText");
					commit = true;
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setName("MY_Text");
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		// select my name
		selectButtonAndApply(MergeConstants.MY_TITLE);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals("MY_Text", blocks[0].getName());

	}

	@Test
	public void testNameConflict2() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setName("LatestText");
					commit = true;
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setName("MY_Text");
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		// select my name
		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals(".text", blocks[0].getName());
	}

	@Test
	public void testNameConflict3() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setName("LatestText");
					commit = true;
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setName("MY_Text");
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		// select my name
		selectButtonAndApply(MergeConstants.LATEST_TITLE);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals("LatestText", blocks[0].getName());
	}

	@Test
	public void testPermissionsConflict() throws Exception {
		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setRead(true);
					blocks[0].setExecute(true);
					blocks[0].setWrite(false);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setWrite(false);
					blocks[0].setExecute(false);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setWrite(true);
					blocks[0].setExecute(true);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		selectButtonAndApply(MergeConstants.MY_TITLE);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertTrue(blocks[0].isExecute());
		assertTrue(blocks[0].isWrite());
	}

	@Test
	public void testPermissionsConflict2() throws Exception {
		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setRead(true);
					blocks[0].setExecute(true);
					blocks[0].setWrite(false);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setWrite(false);
					blocks[0].setExecute(false);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setWrite(true);
					blocks[0].setExecute(true);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertTrue(blocks[0].isExecute());
		assertTrue(!blocks[0].isWrite());
	}

	@Test
	public void testMultipleConflicts() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment("this is a comment for .text");
					blocks[2].setComment("this is a comment for .rsrc");
					blocks[4].setRead(false);
					blocks[4].setWrite(false);
					blocks[4].setExecute(false);

					try {
						blocks[4].setName("special-debug");
					}
					catch (LockException e) {
						Assert.fail();
					}

//					Address baseAddr = program.getMinAddress().getNewAddress(0x03002000L);
//					program.setImageBase(baseAddr, true);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
//				Address baseAddr = program.getMinAddress().getNewAddress(0x2000L);
				try {
//					program.setImageBase(baseAddr, true);
					blocks[0].setComment("MY comments for .text are better");
					blocks[3].setComment("this is a comment for .bound import");
					blocks[4].setRead(true);
					blocks[4].setWrite(false);
					blocks[4].setExecute(true);
					blocks[4].setName("not-used");
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

//		selectButtonAndApply(MergeConstants.MY_TITLE, false); // image base conflict
		selectButtonAndApply(MergeConstants.MY_TITLE, false);// block 0 comment
		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE, false);// block 4 name conflict
		selectButtonAndApply(MergeConstants.LATEST_TITLE, false);// block 4 permission conflict
		waitForCompletion();

//		Address baseAddr = resultProgram.getMinAddress().getNewAddress(0x2000L);
//		assertEquals(baseAddr, resultProgram.getImageBase());

		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals("MY comments for .text are better", blocks[0].getComment());
		assertEquals("this is a comment for .rsrc", blocks[2].getComment());
		assertEquals("this is a comment for .bound import", blocks[3].getComment());
		assertEquals(".debug_data", blocks[5].getName());
		assertTrue(!blocks[4].isRead());
		assertTrue(!blocks[4].isWrite());
		assertTrue(!blocks[4].isExecute());
		assertTrue(!blocks[4].isVolatile());
	}

	@Test
	public void testCommentNoConflict() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// nothing to do
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment(null);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();
		waitForCompletion();

		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertNull(blocks[0].getComment());
	}

	@Test
	public void testNullCommentConflict() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment("this is a comment for .text");
					blocks[2].setComment("this is a comment for .rsrc");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment(null);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		selectButtonAndApply(MergeConstants.MY_TITLE);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertNull(blocks[0].getComment());
		assertEquals("this is a comment for .rsrc", blocks[2].getComment());
	}

	@Test
	public void testCommentConflict() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment("this is a comment for .text");
					blocks[2].setComment("this is a comment for .rsrc");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment("MY comments for .text are better");
					blocks[2].setComment("this is a comment for .rsrc");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		selectButtonAndApply(MergeConstants.MY_TITLE);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals("MY comments for .text are better", blocks[0].getComment());
		assertEquals("this is a comment for .rsrc", blocks[2].getComment());
	}

	@Test
	public void testCommentConflict2() throws Exception {
		mtf.initialize("notepad3", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment("this is a comment for .text");
					blocks[2].setComment("this is a comment for .rsrc");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment("MY comments for .text are better");
					blocks[2].setComment("this is a comment for .rsrc");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		selectButtonAndApply(MergeConstants.MY_TITLE);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals("MY comments for .text are better", blocks[0].getComment());
		assertEquals("this is a comment for .rsrc", blocks[2].getComment());
	}

	@Test
	public void testCommentConflict3() throws Exception {
		mtf.initialize("notepad3", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment("this is a comment for .text");
					blocks[2].setComment("this is a comment for .rsrc");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setComment("MY comments for .text are better");
					blocks[2].setComment("my comments");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		selectButtonAndApply(MergeConstants.MY_TITLE, false);
		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE, false);
		waitForCompletion();

		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals("MY comments for .text are better", blocks[0].getComment());
		assertNull(blocks[2].getComment());
	}

	@Test
	public void testNameConflictDoNotUseForAll() throws Exception {
		setupUseForAllConflicts();
		merge();

		// select each choice and don't UseForAll.
		selectButtonAndApply(MergeConstants.LATEST_TITLE, false);
		selectButtonAndApply(MergeConstants.MY_TITLE, false);
		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE, false);
		waitForCompletion();

		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals("LatestText", blocks[0].getName());
		assertEquals("My_Data", blocks[1].getName());
		assertEquals("comment (1)", blocks[2].getComment());

	}

	@Test
	public void testNameConflictUseForAllPickLatest() throws Exception {
		setupUseForAllConflicts();
		merge();

		// select Latest and UseForAll
		selectButtonAndUseForAllThenApply(MergeConstants.LATEST_TITLE, true);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals("LatestText", blocks[0].getName());
		assertEquals("LatestData", blocks[1].getName());
		assertEquals("LatestResource", blocks[2].getComment());

	}

	@Test
	public void testNameConflictUseForAllPickMy() throws Exception {
		setupUseForAllConflicts();
		merge();

		// select My and UseForAll
		selectButtonAndUseForAllThenApply(MergeConstants.MY_TITLE, true);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals("My_Text", blocks[0].getName());
		assertEquals("My_Data", blocks[1].getName());
		assertEquals("My_Resource", blocks[2].getComment());

	}

	@Test
	public void testNameConflictUseForAllPickOriginal() throws Exception {
		setupUseForAllConflicts();
		merge();

		// select Original and UseForAll
		selectButtonAndUseForAllThenApply(MergeConstants.ORIGINAL_TITLE, true);
		MemoryBlock[] blocks = resultProgram.getMemory().getBlocks();
		assertEquals(".text", blocks[0].getName());

		// note: the name becomes data_1 because there are 2 data blocks in the original program, 
		//       and the merger will create a unique name
		assertEquals(".data_1", blocks[1].getName());
		assertEquals("comment (1)", blocks[2].getComment());

	}

	private void setupUseForAllConflicts() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setName("LatestText");
					blocks[1].setName("LatestData");
					blocks[2].setComment("LatestResource");
					commit = true;
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("test");
				try {
					blocks[0].setName("My_Text");
					blocks[1].setName("My_Data");
					blocks[2].setComment("My_Resource");
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
	}

	private void merge() throws Exception {
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
				throw new AssertException(e);
			}
		});
		t.start();
		waitForPostedSwingRunnables();
	}

	private void waitForCompletion() throws Exception {
		waitForMergeCompletion();
	}

	private PluginTool getMergeTool() {
		waitForMergeTool();
		return mergeTool;
	}

	private void selectButtonAndApply(String text, boolean doWait) throws Exception {

		int count = 0;
		MemoryMergePanel panel = null;
		PluginTool tool = getMergeTool();
		while (panel == null && count < 100) {
			panel = findComponent(tool.getToolFrame(), MemoryMergePanel.class, true);
			Thread.sleep(50);
			++count;
		}
		assertNotNull(panel);

		final JRadioButton rb = (JRadioButton) findButton(panel, text);
		assertNotNull(rb);
		SwingUtilities.invokeAndWait(() -> rb.setSelected(true));
		Window window = windowForComponent(panel);
		JButton applyButton = findButtonByText(window, "Apply");
		assertNotNull(applyButton);

		pressButton(applyButton);
		waitForPostedSwingRunnables();
		resultProgram.flushEvents();
		if (doWait) {
			waitForCompletion();
		}
		else {
			// wait until the panel has been reset
			while (applyButton.isEnabled() && rb.isVisible()) {
				Thread.sleep(250);
			}
		}

	}

	private void selectButtonAndApply(String text) throws Exception {
		selectButtonAndApply(text, true);
	}

	private void selectButtonAndUseForAllThenApply(String text, final boolean useForAll)
			throws Exception {

		boolean doWait = true;
		int count = 0;
		MemoryMergePanel panel = null;
		PluginTool tool = getMergeTool();
		while (panel == null && count < 100) {
			panel = findComponent(tool.getToolFrame(), MemoryMergePanel.class, true);
			Thread.sleep(50);
			++count;
		}
		assertNotNull(panel);

		final JCheckBox useForAllCB = (JCheckBox) getInstanceField("useForAllCB", panel);
		assertNotNull(useForAllCB);
		final JRadioButton rb = (JRadioButton) findButton(panel, text);
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
		if (doWait) {
			waitForCompletion();
		}
		else {
			// wait until the panel has been reset
			while (applyButton.isEnabled() && rb.isVisible()) {
				Thread.sleep(250);
			}
		}
	}

	private AbstractButton findButton(Container container, String text) {
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
