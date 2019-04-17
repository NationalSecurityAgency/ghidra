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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.awt.*;

import javax.swing.*;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.merge.MergeConstants;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.listing.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;

/**
 * Test the tree merger.
 */
public class ProgramTreeMergeManager2Test extends AbstractProgramTreeMergeManagerTest {

	@Test
	public void testNameConflictOpt1() throws Exception {

		// Case 1: "other" name changed, "private" name changed
		// conflict resolution is ASK_USER (private name exists in results tree)
		// Choose "Use name  'Some Other Tree'"
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {
					// for case 1
					listing.renameTree("Main Tree", "Some Other Tree");
					listing.createRootModule("My Tree");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {
					// for case 1
					listing.renameTree("Main Tree", "My Tree");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		// select "Use name 'Another Tree One'
		selectButtonAndApply("Use name 'Some Other Tree' (" + MergeConstants.LATEST_TITLE + ")");

		// result program should have a tree named "Another Tree One"
		assertNotNull(resultProgram.getListing().getRootModule("Some Other Tree"));
	}

	@Test
	public void testNameConflictOpt2() throws Exception {
		// Case 1: "other" name changed, "private" name changed
		// conflict resolution is ASK_USER (private name exists in results tree)
		// Choose option "Rename 'My Tree' to 'My Tree.<sid>'"
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {
					// for case 1
					listing.renameTree("Main Tree", "Some Other Tree");
					listing.createRootModule("My Tree");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {
					// for case 1
					listing.renameTree("Main Tree", "My Tree");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge();

		// select "Rename" option
		String treeName = "My Tree." + SystemUtilities.getUserName();
		selectButtonAndApply("Add tree 'My Tree' (" + MergeConstants.MY_TITLE + ")");

		// result program should have a tree named "My Tree.<sid>"
		assertNotNull(resultProgram.getListing().getRootModule("Some Other Tree"));
		assertNotNull(resultProgram.getListing().getRootModule(treeName));
	}

	@Test
	public void testNameConflictOpt3() throws Exception {
		// Case 1: "other" name changed, "private" name changed
		// Choose option for use original name
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {
					// for case 1
					listing.renameTree("Main Tree", "Some Other Tree");
					listing.createRootModule("My Tree");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {
					// for case 1
					listing.renameTree("Main Tree", "My Tree");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge();

		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE);

		assertNull(resultProgram.getListing().getRootModule("Some Other Tree"));
		String treeName = "My Tree." + SystemUtilities.getUserName();
		assertNull(resultProgram.getListing().getRootModule(treeName));
		assertNotNull(resultProgram.getListing().getRootModule("Main Tree"));
	}

	@Test
	public void testOtherNameContentChangedOpt1() throws Exception {
		// Case 4: "other" name & content changed, "private" name changed
		// Choose "Use name 'Another Tree One'

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {
					// for case 4
					ProgramModule root = listing.getRootModule("Tree One");
					listing.renameTree("Tree One", "Another Tree One");
					root.createModule("submodule");

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {

					// for case 4
					listing.renameTree("Tree One", "My Tree One");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge();

		selectButtonAndApply("Use name 'Another Tree One'");

		// result program should have a tree named "Another Tree One"
		assertNotNull(resultProgram.getListing().getRootModule("Another Tree One"));

	}

	@Test
	public void testOtherNameContentChangedOpt2() throws Exception {
		// Case 4: "other" name & content changed, "private" name changed
		// Choose "Use name 'My Tree One'

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {
					// for case 4
					ProgramModule root = listing.getRootModule("Tree One");
					listing.renameTree("Tree One", "Another Tree One");
					root.createModule("submodule");

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {

					// for case 4
					listing.renameTree("Tree One", "My Tree One");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge();

		selectButtonAndApply("Use name 'My Tree One'");

		// result program should have a tree named "My Tree One"
		assertNull(resultProgram.getListing().getRootModule("Another Tree One"));
		assertNotNull(resultProgram.getListing().getRootModule("My Tree One"));
	}

	@Test
	public void testOtherNameContentChangedOpt3() throws Exception {
		// Case 4: "other" name & content changed, "private" name changed
		// Choose "Add new tree named 'My Tree One'

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {
					// for case 4
					ProgramModule root = listing.getRootModule("Tree One");
					listing.renameTree("Tree One", "Another Tree One");
					root.createModule("submodule");

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {

					// for case 4
					listing.renameTree("Tree One", "My Tree One");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge();

		selectButtonAndApply("Add new tree");

		// result program should have a tree named "My Tree One"
		assertNotNull(resultProgram.getListing().getRootModule("Another Tree One"));
		assertNotNull(resultProgram.getListing().getRootModule("My Tree One"));
	}

	@Test
	public void testOtherNameContentChangedOpt4() throws Exception {
		// Case 4: "other" name & content changed, "private" name changed
		// Choose original name

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {
					// for case 4
					ProgramModule root = listing.getRootModule("Tree One");
					listing.renameTree("Tree One", "Another Tree One");
					root.createModule("submodule");

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {

					// for case 4
					listing.renameTree("Tree One", "My Tree One");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		merge();

		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE);

		// result program should have a tree named "Another Tree One"
		assertNotNull(resultProgram.getListing().getRootModule("Another Tree One"));
		ProgramModule root = resultProgram.getListing().getRootModule("Tree One");
		assertNotNull(root);
		Group[] kids = root.getChildren();
		for (Group kid : kids) {
			if (kid.getName().equals("submodule")) {
				Assert.fail("tree should not have a module, submodule");
				break;
			}
		}
	}

	@Test
	public void testOtherPrivateNameContentChangedOpt1() throws Exception {
		// Case 5: "other" name changed, "private" name & content changed
		// Choose option "Use name 'Another Tree Two'"
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {

					// for case 5
					listing.renameTree("Tree Two", "Another Tree Two");

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {

					// for case 5
					ProgramModule root = listing.getRootModule("Tree Two");
					listing.renameTree("Tree Two", "My Tree Two");
					root.createModule("my submodule");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		selectButtonAndApply("Use name 'Another Tree Two'");

		// result program should have a tree named "My Tree One"
		assertNotNull(resultProgram.getListing().getRootModule("Another Tree Two"));
		assertNull(resultProgram.getListing().getRootModule("Tree Two"));
		assertNull(resultProgram.getListing().getRootModule("My Tree Two"));
	}

	@Test
	public void testOtherPrivateNameContentChangedOpt2() throws Exception {
		// Case 5: "other" name changed, "private" name & content changed
		// Choose option "Use name 'My Tree Two'"
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {

					// for case 5
					listing.renameTree("Tree Two", "Another Tree Two");

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {

					// for case 5
					ProgramModule root = listing.getRootModule("Tree Two");
					listing.renameTree("Tree Two", "My Tree Two");
					root.createModule("my submodule");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		selectButtonAndApply("Use name 'My Tree Two'");

		// result program should have a tree named "My Tree One"
		assertNull(resultProgram.getListing().getRootModule("Another Tree Two"));
		assertNull(resultProgram.getListing().getRootModule("Tree Two"));
		assertNotNull(resultProgram.getListing().getRootModule("My Tree Two"));
	}

	@Test
	public void testOtherPrivateNameContentChangedOpt3() throws Exception {
		// Case 5: "other" name changed, "private" name & content changed
		// Choose option "Add new tree named 'My Tree Two'"
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {

					// for case 5
					listing.renameTree("Tree Two", "Another Tree Two");

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {

					// for case 5
					ProgramModule root = listing.getRootModule("Tree Two");
					listing.renameTree("Tree Two", "My Tree Two");
					root.createModule("my submodule");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		merge();

		selectButtonAndApply("Add new tree");

		// result program should have a tree named "My Tree One"
		assertNotNull(resultProgram.getListing().getRootModule("Another Tree Two"));
		assertNull(resultProgram.getListing().getRootModule("Tree Two"));
		assertNotNull(resultProgram.getListing().getRootModule("My Tree Two"));
	}

	@Test
	public void testContentsNamesChanged() throws Exception {

		// case 7: dest name and content changed, source name and content changed
		// test for name conflict
		// conflict resolution = ORIGINAL
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {
					ProgramModule root = listing.getRootModule("Main Tree");
					root.createFragment("frag_one");
					root.createModule("my module");
					listing.renameTree("Main Tree", "My Tree");
					listing.createRootModule("Another Main Tree");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				boolean commit = false;
				int transactionID = program.startTransaction("test");
				try {
					Listing listing = program.getListing();

					ProgramModule m = listing.getModule("Main Tree", "Strings");

					ProgramFragment textFrag = listing.getFragment("Main Tree", ".text");
					// create a module
					m = m.createModule("my new module");
					// create a fragment under "my new module" 
					ProgramFragment frag = m.createFragment("my fragment");
					try {
						frag.move(textFrag.getMinAddress(), textFrag.getMaxAddress());
					}
					catch (NotFoundException e1) {
						Assert.fail("Got NotFoundException!");
					}
					// rename tree to cause a conflict
					listing.renameTree("Main Tree", "Another Main Tree");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		merge();

		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE);

		assertNotNull(resultProgram.getListing().getRootModule("Main Tree"));
		assertNotNull(resultProgram.getListing().getModule("My Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("My Tree", "frag_one"));
		String newName = "Another Main Tree." + System.getProperty("user.name");

		assertNotNull(resultProgram.getListing().getRootModule("Another Main Tree"));
		assertNull(resultProgram.getListing().getModule(newName, "my new module"));
		assertNull(resultProgram.getListing().getFragment(newName, "my fragment"));
	}

	@Test
	public void testMultipleConflicts() throws Exception {

		// case 7: dest name and content changed, source name and content changed
		// test for name conflict
		// conflict resolution = ORIGINAL
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				try {
					ProgramModule root = listing.getRootModule("Main Tree");
					root.createFragment("frag_one");
					root.createModule("my module");
					listing.renameTree("Main Tree", "My Tree");
					listing.createRootModule("Another Main Tree");

					// rename Tree Three to Tree3_XXX
					listing.renameTree("Tree Three", "Tree3_XXX");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				boolean commit = false;
				int transactionID = program.startTransaction("test");
				try {
					Listing listing = program.getListing();

					ProgramModule m = listing.getModule("Main Tree", "Strings");

					ProgramFragment textFrag = listing.getFragment("Main Tree", ".text");
					// create a module
					m = m.createModule("my new module");
					// create a fragment under "my new module" 
					ProgramFragment frag = m.createFragment("my fragment");
					try {
						frag.move(textFrag.getMinAddress(), textFrag.getMaxAddress());
					}
					catch (NotFoundException e1) {
						Assert.fail("Got NotFoundException!");
					}
					// rename tree to cause a conflict
					listing.renameTree("Main Tree", "My Main Tree");

					listing.renameTree("Tree Three", "MY TREE 3");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		merge();
		// For some reason the order of processing program tree conflicts changed.
		// Perhaps the IDs for the trees changed? Anyway I swapped the following 2 lines to get test to work.
		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE, false);// Use name "Main Tree", lose "My Main Tree"
		selectButtonAndApply(MergeConstants.LATEST_TITLE, true);// Use "Tree3_XXX", lose "MY TREE 3"

		Listing listing = resultProgram.getListing();
		// Tree3_XXX should exist
		assertNotNull(listing.getRootModule("Tree3_XXX"));
		// MY TREE 3 should not exist
		assertNull(listing.getRootModule("MY TREE 3"));

		// Tree Three should not exist 
		assertNull(listing.getRootModule("Tree Three"));

		// "Main Tree" should exist
		assertNotNull(listing.getRootModule("Main Tree"));
		// Another Main Tree should not exist
		assertNull(listing.getRootModule("My Main Tree"));

		// Another Main Tree.<user name> should not exist
		assertNull(listing.getRootModule("My Main Tree." + SystemUtilities.getUserName()));
		// My Tree should exist because Main Tree was renamed to "My Tree"
		assertNotNull(listing.getRootModule("My Tree"));
	}

	private void selectButtonAndApply(String text, boolean doWait) throws Exception {

		waitForMergeTool();

		Window window = waitForWindow(JDialog.class);
		assertNotNull(window);

		// wait until the merge panel shows up
		waitFor(() -> findComponent(window, ProgramTreeMergePanel.class),
			"ProgramTreeMergePanel never appeared");

		JRadioButton rb = (JRadioButton) findButton(window, text);
		assertNotNull("Could not find button '" + text + "'", rb);
		SwingUtilities.invokeAndWait(() -> rb.setSelected(true));
		JButton applyButton = (JButton) findButton(window, "Apply");
		assertNotNull(applyButton);

		waitForCondition(() -> applyButton.isEnabled(), "Apply button never became enabled");

		pressButton(applyButton);
		waitForPostedSwingRunnables();
		resultProgram.flushEvents();

		if (doWait) {
			waitForMergeCompletion();
		}
	}

	private void selectButtonAndApply(String text) throws Exception {
		selectButtonAndApply(text, true);
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
