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

import static org.junit.Assert.*;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;

/**
 * Test the tree merger.
 * 
 * 
 */
public class ProgramTreeMergeManager1Test extends AbstractProgramTreeMergeManagerTest {

	@Test
    public void testNoConflicts() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes for Latest.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				// make a change to "Main Tree"
				ProgramModule root = listing.getRootModule("Main Tree");

				int transactionID = program.startTransaction("test");

				try {
					ProgramModule m = root.createModule("A");
					m.createModule("SubModule-a");
					mainTreeCount = root.getNumChildren();

					// make a change to "Tree Three"
					root = listing.getRootModule("Tree Three");
					m = root.createModule("BModule");
					treeThreeCount = root.getNumChildren();

					m.createModule("SubModule-b");
					m.createFragment("empty");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}

			}
		});

		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("Main Tree");
		assertEquals(mainTreeCount, root.getNumChildren());

		ProgramModule m = resultProgram.getListing().getModule("Main Tree", "SubModule-a");
		assertNotNull(m);
		assertEquals(1, m.getNumParents());

		root = resultProgram.getListing().getRootModule("Tree Three");
		assertEquals(treeThreeCount, root.getNumChildren());
		m = resultProgram.getListing().getModule("Tree Three", "SubModule-b");
		assertNotNull(m);
		assertEquals(1, m.getNumParents());
		assertEquals("BModule", m.getParents()[0].getName());
	}

	@Test
    public void testTreeAdded() throws Exception {
		// case 14: new tree added to source
		// (Not a conflict)
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes for Latest.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				try {
					ProgramModule root = listing.createRootModule("Tree Four");
					root.createFragment("empty");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("Tree Four");
		assertNotNull(root);
		// 5 fragments for the blocks + 1 for "empty" fragment

		assertEquals(6, root.getNumChildren());
		assertNotNull(resultProgram.getListing().getFragment("Tree Four", "empty"));
	}

	@Test
    public void testTreeAdded2() throws Exception {
		// case 14: new tree added to source
		// (Not a conflict)
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				try {
					listing.createRootModule("My Tree");
					listing.createRootModule("Another Tree");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
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
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				try {
					ProgramModule root = listing.createRootModule("Another Tree");
					root.createFragment("empty");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("My Tree");
		assertNotNull(root);
		assertEquals(5, root.getNumChildren());
		String newName = "Another Tree." + SystemUtilities.getUserName();
		assertNotNull(resultProgram.getListing().getRootModule(newName));
		assertNotNull(resultProgram.getListing().getFragment(newName, "empty"));

	}

	@Test
    public void testTreeAdded3() throws Exception {
		// case 14: new tree added to source
		// (Not a conflict)
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				try {
					listing.createRootModule("Tree B2");
					listing.createRootModule("Tree B3");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
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
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				try {
					ProgramModule root = listing.createRootModule("Tree B3");
					root.createFragment("empty");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge();

		assertNotNull(resultProgram.getListing().getRootModule("Tree B3"));
		String newName = "Tree B3." + SystemUtilities.getUserName();
		assertNotNull(resultProgram.getListing().getRootModule(newName));
		assertNotNull(resultProgram.getListing().getFragment(newName, "empty"));

	}

	@Test
    public void testTreeAddedAndDeleted() throws Exception {
		// case 14: new tree added to source, then deleted
		// (Not a conflict)
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				try {
					listing.createRootModule("Tree B2");
					listing.createRootModule("Tree B3");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
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
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				try {
					ProgramModule root = listing.createRootModule("Tree B3");
					root.createFragment("empty");
					listing.removeTree("Tree B3");
					listing.createRootModule("Tree B4");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge();

		assertNotNull(resultProgram.getListing().getRootModule("Tree B3"));
		assertNotNull(resultProgram.getListing().getRootModule("Tree B4"));
	}

	@Test
    public void testTreeAddVsNameChangeAutoMerge() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				try {
					listing.createRootModule("Tree B3");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
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
					Listing listing = program.getListing();
					listing.renameTree("Program Tree", "Tree B3");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		String newName = "Tree B3." + SystemUtilities.getUserName();
		resultProgram = mtf.getResultProgram();// destination program
		assertNotNull(resultProgram.getListing().getRootModule("Program Tree"));
		assertNotNull(resultProgram.getListing().getRootModule("Tree B3"));
		assertNull(resultProgram.getListing().getRootModule(newName));

		executeMerge(ProgramTreeMergeManager.KEEP_OTHER_NAME);

		assertNull(resultProgram.getListing().getRootModule("Program Tree"));
		assertNotNull(resultProgram.getListing().getRootModule("Tree B3"));
		assertNotNull(resultProgram.getListing().getRootModule(newName));

	}

	@Test
    public void testTreeAndModuleAdditions() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes for Latest.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Listing listing = program.getListing();

					ProgramModule root = listing.createRootModule("Tree Four");
					root.createModule("Module-A");
					root.createModule("Module-B");
					ProgramFragment frag = listing.getFragment("Tree Four", ".text");
					frag.setName(".text-A");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("Tree Four");
		assertNotNull(root);
		// 5 fragments for the blocks plus 2 modules created above
		assertEquals(7, root.getNumChildren());

		ProgramFragment frag = resultProgram.getListing().getFragment("Tree Four", ".text-A");
		assertNotNull(frag);
	}

	@Test
    public void testPrivateNameChanged() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes for Latest.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Listing listing = program.getListing();
					listing.renameTree("Tree Three", "Another Tree Three");

				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("Another Tree Three");
		assertNotNull(root);
		int childCount =
			myProgram.getListing().getRootModule("Another Tree Three").getNumChildren();
		assertEquals(childCount, root.getNumChildren());
	}

	@Test
    public void testNameAndStructureChanged() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes for Latest.
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
		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("Another Main Tree");
		assertNotNull(root);
		Address addr = resultProgram.getMinAddress().getNewAddress(0x0100101c);
		ProgramFragment frag = resultProgram.getListing().getFragment("Another Main Tree", addr);
		assertNotNull(frag);
		assertEquals("my fragment", frag.getName());

		// "Main Tree" should have gotten removed
		assertNull(resultProgram.getListing().getRootModule("Main Tree"));
	}

	@Test
    public void testNamesContentChanged1() throws Exception {
		// Case 4: "other" name AND content changed, "private" name changed
		// conflict resolution = KEEP_OTHER_NAME
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				// change name and module structure
				try {
					ProgramModule root = listing.getRootModule("Main Tree");
					listing.renameTree("Main Tree", "Some Other Tree");
					root.createModule("my sub module");

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

					// change the name					
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
		// conflict resolution option is to keep other name
		executeMerge(ProgramTreeMergeManager.KEEP_OTHER_NAME);
		// should have "Some Other Tree" 
		ProgramModule root = resultProgram.getListing().getRootModule("Some Other Tree");
		assertNotNull(root);
		assertNotNull(resultProgram.getListing().getModule("Some Other Tree", "my sub module"));
		assertNull(resultProgram.getListing().getRootModule("Another Main Tree"));

	}

	@Test
    public void testNamesContentChanged2() throws Exception {
		// Case 4: "other" name AND content changed, "private" name changed
		// conflict resolution = KEEP_PRIVATE_NAME
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				// change name and module structure
				try {
					ProgramModule root = listing.getRootModule("Main Tree");
					listing.renameTree("Main Tree", "Some Other Tree");
					root.createModule("my sub module");

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

					// change the name					
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
		executeMerge(ProgramTreeMergeManager.KEEP_PRIVATE_NAME);
		// should not have "Some Other Tree" 
		assertNull(resultProgram.getListing().getRootModule("Some Other Tree"));
		assertNotNull(resultProgram.getListing().getRootModule("Another Main Tree"));

		assertNotNull(resultProgram.getListing().getModule("Another Main Tree", "my sub module"));
	}

	@Test
    public void testNamesContentChanged3() throws Exception {
		// Case 4: "other" name AND content changed, "private" name changed
		// conflict resolution = ADD_NEW_TREE
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				// change name and module structure
				try {
					ProgramModule root = listing.getRootModule("Main Tree");
					listing.renameTree("Main Tree", "Some Other Tree");
					root.createModule("my sub module");

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

					// change the name					
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

		executeMerge(ProgramTreeMergeManager.ADD_NEW_TREE);
		// should  have "Some Other Tree" and "Another Main Tree" 
		assertNotNull(resultProgram.getListing().getRootModule("Some Other Tree"));
		assertNotNull(resultProgram.getListing().getRootModule("Another Main Tree"));

		assertNotNull(resultProgram.getListing().getModule("Some Other Tree", "my sub module"));
	}

	@Test
    public void testNamesContentChanged4() throws Exception {
		// Case 4: "other" name AND content changed, "private" name changed
		// conflict resolution = RENAME_PRIVATE
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("test");
				// change name and module structure
				try {
					ProgramModule root = listing.getRootModule("Main Tree");
					listing.renameTree("Main Tree", "Some Other Tree");
					root.createModule("my sub module");
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

					// change the name					
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

		executeMerge(ProgramTreeMergeManager.RENAME_PRIVATE);
		// should  have "Some Other Tree" and "Another Main Tree.<sid>"
		String newName = "Another Main Tree." + System.getProperty("user.name");
		assertNotNull(resultProgram.getListing().getRootModule("Some Other Tree"));
		assertNotNull(resultProgram.getListing().getRootModule(newName));

		assertNotNull(resultProgram.getListing().getModule("Some Other Tree", "my sub module"));
	}

	@Test
    public void testConflictNameAndStructureChanged1() throws Exception {
		// Case 5: other name changed, private name and content changed
		// conflict resolution = KEEP_OTHER_NAME
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
					listing.renameTree("Main Tree", "Some Other Tree");
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
		// conflict resolution option is to keep other name
		executeMerge(ProgramTreeMergeManager.KEEP_OTHER_NAME);
		ProgramModule root = resultProgram.getListing().getRootModule("Some Other Tree");
		assertNotNull(root);
		Address addr = resultProgram.getMinAddress().getNewAddress(0x0100101c);
		ProgramFragment frag = resultProgram.getListing().getFragment("Some Other Tree", addr);
		assertNotNull(frag);
		assertEquals("my fragment", frag.getName());

		assertNull(resultProgram.getListing().getRootModule("Another Main Tree"));
	}

	@Test
    public void testConflictNameAndStructureChanged2() throws Exception {
		// Case 5: other name changed, private name and content changed
		// conflict resolution = KEEP_PRIVATE_NAME

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
					listing.renameTree("Main Tree", "Some Other Tree");
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
		// conflict resolution option is to keep private name
		executeMerge(ProgramTreeMergeManager.KEEP_PRIVATE_NAME);
		ProgramModule root = resultProgram.getListing().getRootModule("Some Other Tree");
		assertNull(root);
		Address addr = resultProgram.getMinAddress().getNewAddress(0x0100101c);
		ProgramFragment frag = resultProgram.getListing().getFragment("Another Main Tree", addr);
		assertNotNull(frag);
		assertEquals("my fragment", frag.getName());
	}

	@Test
    public void testConflictNameAndStructureChanged3() throws Exception {
		// Case 5: other name changed, private name and content changed
		// conflict resolution = ADD_NEW_TREE

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
					listing.renameTree("Main Tree", "Some Other Tree");
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
		// conflict resolution option is to add a new tree
		executeMerge(ProgramTreeMergeManager.ADD_NEW_TREE);
		ProgramModule root = resultProgram.getListing().getRootModule("Some Other Tree");
		assertNotNull(root);
		Address addr = resultProgram.getMinAddress().getNewAddress(0x0100101c);
		assertNotNull(resultProgram.getListing().getRootModule("Another Main Tree"));
		ProgramFragment frag = resultProgram.getListing().getFragment("Another Main Tree", addr);
		assertNotNull(frag);
		assertEquals("my fragment", frag.getName());
	}

	@Test
    public void testConflictNameAndStructureChanged4() throws Exception {
		// Case 5: other name changed, private name and content changed
		// conflict resolution = RENAME_PRIVATE
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
					listing.renameTree("Main Tree", "Some Other Tree");
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
		executeMerge(ProgramTreeMergeManager.RENAME_PRIVATE);
		ProgramModule root = resultProgram.getListing().getRootModule("Some Other Tree");
		assertNotNull(root);
		Address addr = resultProgram.getMinAddress().getNewAddress(0x0100101c);
		assertNotNull(resultProgram.getListing().getRootModule("Another Main Tree"));
		ProgramFragment frag = resultProgram.getListing().getFragment("Another Main Tree", addr);
		assertNotNull(frag);
		assertEquals("my fragment", frag.getName());
	}

	@Test
    public void testContentsChanged1() throws Exception {
		// case 6: both contents changed
		// conflict resolution = KEEP_OTHER_NAME
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
		executeMerge(ProgramTreeMergeManager.KEEP_OTHER_NAME);
		assertNotNull(resultProgram.getListing().getModule("Main Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("Main Tree", "frag_one"));

		assertNull(resultProgram.getListing().getModule("Main Tree", "my new module"));
		assertNull(resultProgram.getListing().getFragment("Main Tree", "my fragment"));

	}

	@Test
    public void testContentsChanged2() throws Exception {
		// case 6: both contents changed
		// conflict resolution = ADD_NEW_TREE
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
		executeMerge(ProgramTreeMergeManager.ADD_NEW_TREE);
		assertNotNull(resultProgram.getListing().getModule("Main Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("Main Tree", "frag_one"));
		String newName = "Main Tree." + System.getProperty("user.name");
		assertNotNull(resultProgram.getListing().getModule(newName, "my new module"));
		assertNotNull(resultProgram.getListing().getFragment(newName, "my fragment"));

	}

	@Test
    public void testContentsChanged4() throws Exception {
		// case 6: both contents changed
		// conflict resolution = ADD_NEW_TREE
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
		executeMerge(ProgramTreeMergeManager.RENAME_PRIVATE);
		assertNotNull(resultProgram.getListing().getModule("Main Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("Main Tree", "frag_one"));
		String newName = "Main Tree." + System.getProperty("user.name");
		assertNotNull(resultProgram.getListing().getModule(newName, "my new module"));
		assertNotNull(resultProgram.getListing().getFragment(newName, "my fragment"));

	}

	@Test
    public void testContentsChanged3() throws Exception {
		// case 6: both contents changed
		// conflict resolution = ORIGINAL_NAME
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
		executeMerge(ProgramTreeMergeManager.ORIGINAL_NAME);
		// should have original tree
		String treeName = "Main Tree." + SystemUtilities.getUserName();
		assertNotNull(resultProgram.getListing().getRootModule(treeName));
		assertNull(resultProgram.getListing().getModule(treeName, "my new module"));

		assertNotNull(resultProgram.getListing().getModule("Main Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("Main Tree", "frag_one"));

		assertNull(resultProgram.getListing().getModule("Main Tree", "my new module"));
		assertNull(resultProgram.getListing().getFragment("Main Tree", "my fragment"));

	}

	@Test
    public void testContentsNamesChanged1() throws Exception {
		// case 7: both contents changed and both names changed
		// conflict resolution = KEEP_OTHER_NAME
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
		// should keep other and lose private changes
		executeMerge(ProgramTreeMergeManager.KEEP_OTHER_NAME);
		assertNotNull(resultProgram.getListing().getModule("My Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("My Tree", "frag_one"));

		assertNull(resultProgram.getListing().getModule("My Tree", "my new module"));
		assertNull(resultProgram.getListing().getRootModule("Another Main Tree"));
	}

	@Test
    public void testContentsNamesChanged2() throws Exception {

		// case 7: dest name and content changed, source name and content changed
		// test for name conflict
		// conflict resolution = ADD_NEW_TREE
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
		// should have private changes in the result with .username appended to the name
		executeMerge(ProgramTreeMergeManager.ADD_NEW_TREE);
		assertNotNull(resultProgram.getListing().getModule("My Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("My Tree", "frag_one"));
		String newName = "Another Main Tree." + System.getProperty("user.name");
		assertNotNull(resultProgram.getListing().getRootModule("Another Main Tree"));
		assertNotNull(resultProgram.getListing().getModule(newName, "my new module"));
		assertNotNull(resultProgram.getListing().getFragment(newName, "my fragment"));
	}

	@Test
    public void testContentsNamesChanged2a() throws Exception {

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
		// should have original tree back in RESULT
		executeMerge(ProgramTreeMergeManager.ORIGINAL_NAME);

		assertNotNull(resultProgram.getListing().getRootModule("Main Tree"));
		assertNotNull(resultProgram.getListing().getModule("My Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("My Tree", "frag_one"));
		String newName = "Another Main Tree." + System.getProperty("user.name");

		assertNotNull(resultProgram.getListing().getRootModule("Another Main Tree"));
		assertNull(resultProgram.getListing().getModule(newName, "my new module"));
		assertNull(resultProgram.getListing().getFragment(newName, "my fragment"));
	}

	@Test
    public void testContentsNamesChanged3() throws Exception {
		// case 7: both contents changed
		// * no name conflicts *
		// conflict resolution = ADD_NEW_TREE
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
		// should have private changes in the result
		executeMerge(ProgramTreeMergeManager.ADD_NEW_TREE);
		assertNotNull(resultProgram.getListing().getModule("My Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("My Tree", "frag_one"));

		assertNotNull(resultProgram.getListing().getRootModule("Another Main Tree"));
		assertNotNull(resultProgram.getListing().getModule("Another Main Tree", "my new module"));
		assertNotNull(resultProgram.getListing().getFragment("Another Main Tree", "my fragment"));
	}
}
