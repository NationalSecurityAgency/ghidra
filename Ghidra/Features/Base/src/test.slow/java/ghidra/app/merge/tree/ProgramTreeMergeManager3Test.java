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
import ghidra.program.model.listing.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.*;

/**
 * More tree tests
 */
public class ProgramTreeMergeManager3Test extends AbstractProgramTreeMergeManagerTest {

	@Test
	public void testDestNameContentsChanged1() throws Exception {
		// case 8: dest name & content changed, private content changed	
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
	public void testDestNameContentsChanged2() throws Exception {
		// case 8: dest name & content changed, private content changed	
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
		// should keep other and add private tree 
		executeMerge(ProgramTreeMergeManager.ADD_NEW_TREE);
		assertNotNull(resultProgram.getListing().getModule("My Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("My Tree", "frag_one"));

		assertNotNull(resultProgram.getListing().getRootModule("Main Tree"));
		assertNotNull(resultProgram.getListing().getModule("Main Tree", "my new module"));
		assertNotNull(resultProgram.getListing().getFragment("Main Tree", "my fragment"));
	}

	@Test
	public void testDestNameContentsChanged3() throws Exception {
		// case 8: dest name & content changed, private content changed	
		// * name conflict *
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
					listing.createRootModule("Main Tree");
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
		// should keep other and add private tree with .username appended to the name
		executeMerge(ProgramTreeMergeManager.ADD_NEW_TREE);
		assertNotNull(resultProgram.getListing().getModule("My Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("My Tree", "frag_one"));

		String newName = "Main Tree." + System.getProperty("user.name");
		assertNotNull(resultProgram.getListing().getRootModule(newName));
		assertNotNull(resultProgram.getListing().getModule(newName, "my new module"));
		assertNotNull(resultProgram.getListing().getFragment(newName, "my fragment"));
	}

	@Test
	public void testDestNameContentsChanged4() throws Exception {
		// case 8: dest name & content changed, private content changed	
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
		// should keep other and add original tree back ing
		executeMerge(ProgramTreeMergeManager.ORIGINAL_NAME);
		assertNotNull(resultProgram.getListing().getModule("My Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("My Tree", "frag_one"));

		assertNotNull(resultProgram.getListing().getRootModule("Main Tree"));
		assertNull(resultProgram.getListing().getModule("Main Tree", "my new module"));
		assertNull(resultProgram.getListing().getFragment("Main Tree", "my fragment"));
		assertNull(resultProgram.getListing().getModule("Main Tree", "my module"));
		assertNull(resultProgram.getListing().getFragment("Main Tree", "frag_one"));
	}

	@Test
	public void testNameContentsChanged1() throws Exception {
		// case 9: dest content changed, private name change and content changed	
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
		assertNotNull(resultProgram.getListing().getModule("Main Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("Main Tree", "frag_one"));
		assertNull(resultProgram.getListing().getRootModule("Another Main Tree"));
		assertNull(resultProgram.getListing().getModule("Another Main Tree", "my new module"));
		assertNull(resultProgram.getListing().getRootModule("Another Main Tree"));
	}

	@Test
	public void testNameContentsChanged2() throws Exception {
		// case 9: dest content changed, private name change and content changed	
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
		assertNotNull(resultProgram.getListing().getModule("Main Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("Main Tree", "frag_one"));

		assertNotNull(resultProgram.getListing().getRootModule("Another Main Tree"));
		assertNotNull(resultProgram.getListing().getModule("Another Main Tree", "my new module"));
		assertNotNull(resultProgram.getListing().getFragment("Another Main Tree", "my fragment"));

	}

	@Test
	public void testNameContentsChanged3() throws Exception {
		// case 9: dest content changed, private name change and content changed	
		// * no name conflicts *
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
		// should not have private changes in the result; put original back in
		// (will have a name conflict since name was not changed in LATEST)
		executeMerge(ProgramTreeMergeManager.ORIGINAL_NAME);

		assertNotNull(
			resultProgram.getListing().getRootModule("Main Tree." + SystemUtilities.getUserName()));

		assertNotNull(resultProgram.getListing().getModule("Main Tree", "my module"));
		assertNotNull(resultProgram.getListing().getFragment("Main Tree", "frag_one"));

		assertNull(resultProgram.getListing().getRootModule("Another Main Tree"));

	}

	@Test
	public void testOtherTreeDeleted() throws Exception {
		// test Case 10: other deleted tree, 
		//	source structure changed or name changed (doesn't matter)
		// result should be to keep the tree
		//
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("test");
				try {
					Listing listing = program.getListing();
					listing.removeTree("Tree One");
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
				ProgramModule root = listing.getRootModule("Tree One");
				try {
					root.createModule("my module");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				program.endTransaction(transactionID, true);
			}
		});
		// Tree One should still exist
		executeMerge();
		assertNotNull(resultProgram.getListing().getRootModule("Tree One"));
		assertNotNull(resultProgram.getListing().getModule("Tree One", "my module"));
	}

	@Test
	public void testOtherTreeChangedDeleted() throws Exception {
		// case 11: dest tree has changes (doesn't matter what kind), 
		//          source tree was deleted;
		// result should be to keep the tree
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				ProgramModule root = listing.getRootModule("Tree One");
				try {
					root.createFragment("my fragment");
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
					listing.removeTree("Tree One");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		// Tree One should still exist
		executeMerge();
		assertNotNull(resultProgram.getListing().getRootModule("Tree One"));
		assertNotNull(resultProgram.getListing().getFragment("Tree One", "my fragment"));
	}

	@Test
	public void testBothTreesDeleted() throws Exception {
		// case 12: both trees were deleted
		// result should be that the tree is still deleted after the merge
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();

				int transactionID = program.startTransaction("test");
				try {
					listing.removeTree("Tree One");
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
					listing.removeTree("Tree One");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		// tree should not exist
		executeMerge();
		assertNull(resultProgram.getListing().getRootModule("Tree One"));
	}

	@Test
	public void testTreeAddedToDestination() throws Exception {
		// case 13: new tree was added to destination,
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
					listing.createRootModule("Tree Four");
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
				// No changes for Checked Out.
			}
		});
		executeMerge();
		assertNotNull(resultProgram.getListing().getRootModule("Tree Four"));
	}

	@Test
	public void testTreeDeleted() throws Exception {
		// case 15: no change to dest tree, source tree is deleted
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
					listing.removeTree("Tree Three");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("Tree Three");
		assertNull(root);
	}

	@Test
	public void testTreeAddedDeleted() throws Exception {
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
					listing.createRootModule("My Tree");
					listing.removeTree("My Tree");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("My Tree");
		assertNull(root);
	}

	@Test
	public void testDeleteModule() throws Exception {
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
				ProgramModule root = listing.getRootModule("Main Tree");
				try {
					root.removeChild("Strings");
				}
				catch (NotEmptyException e) {
					Assert.fail("Got Not Empty exeception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("Main Tree");
		assertNotNull(root);
		Group[] kids = root.getChildren();
		boolean found = false;
		for (Group kid : kids) {
			if (kid.getName().equals("Strings")) {
				found = true;
				break;
			}
		}
		assertTrue(!found);
	}

	@Test
	public void testDeleteFragment() throws Exception {
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
				ProgramModule root = listing.getRootModule("Main Tree");
				ProgramModule m = listing.getModule("Main Tree", "Strings");
				ProgramFragment fragment = listing.getFragment("Main Tree", ".text");
				try {
					try {
						m.add(fragment);
					}
					catch (DuplicateGroupException e1) {
						Assert.fail("Got Duplicate group exception!");
					}
					// remove fragment from root
					try {
						root.removeChild(".text");
					}
					catch (NotEmptyException e) {
						Assert.fail("Got Not Empty exeception!");
					}
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		executeMerge();

		ProgramModule root = resultProgram.getListing().getRootModule("Main Tree");
		assertNotNull(root);
		Group[] kids = root.getChildren();
		boolean found = false;
		for (Group kid : kids) {
			if (kid.getName().equals(".text")) {
				found = true;
				break;
			}
		}
		assertTrue(!found);

		ProgramFragment fragment = resultProgram.getListing().getFragment("Main Tree", ".text");
		assertNotNull(fragment);
		String[] parentNames = fragment.getParentNames();
		found = false;
		for (String parentName : parentNames) {
			if (parentName.equals("Strings")) {
				found = true;
				break;
			}
		}
		assertTrue(found);
	}

	@Test
	public void testBothNamesChanged1() throws Exception {
		// Case 1: "other" name changed, "private" name changed
		// conflict resolution is KEEP_OTHER

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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {
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
		executeMerge(ProgramTreeMergeManager.KEEP_OTHER_NAME);
		// should get "Some Other Tree" only
		ProgramModule root = resultProgram.getListing().getRootModule("Some Other Tree");
		assertNotNull(root);
		assertNull(resultProgram.getListing().getRootModule("My Tree"));
	}

	@Test
	public void testBothNamesChanged2() throws Exception {
		// Case 1: "other" name changed, "private" name changed
		// conflict resolution is KEEP_PRIVATE_NAME

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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {
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
		executeMerge(ProgramTreeMergeManager.KEEP_PRIVATE_NAME);
		// should get "My Tree" only
		assertNull(resultProgram.getListing().getRootModule("Some Other Tree"));
		assertNotNull(resultProgram.getListing().getRootModule("My Tree"));
	}

	@Test
	public void testBothNamesChanged3() throws Exception {
		// Case 1: "other" name changed, "private" name changed
		// conflict resolution is ADD_NEW_TREE

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
				Listing listing = program.getListing();
				// change the name
				int transactionID = program.startTransaction("test");
				try {
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
		executeMerge(ProgramTreeMergeManager.ADD_NEW_TREE);
		// should get "Some Other Tree" and "My Tree"
		assertNotNull(resultProgram.getListing().getRootModule("Some Other Tree"));
		assertNotNull(resultProgram.getListing().getRootModule("My Tree"));
	}

	@Test
	public void testBothNamesChanged4() throws Exception {
		// Case 1: "other" name changed, "private" name changed
		// conflict resolution is RENAME_PRIVATE (private name exists in results tree)

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
		executeMerge(ProgramTreeMergeManager.RENAME_PRIVATE);

		waitForPostedSwingRunnables();
		resultProgram.flushEvents();
		Thread.sleep(1000);

		// should  get "Some Other Tree" and "My Tree"
		assertNotNull(resultProgram.getListing().getRootModule("Some Other Tree"));
		String newName = "My Tree." + System.getProperty("user.name");
		assertNotNull(resultProgram.getListing().getRootModule(newName));
	}

	@Test
	public void testNameContentChanged() throws Exception {
		// Case 2: "other" name changed, "private" content changed
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
				Listing listing = program.getListing();
				// change my content
				int transactionID = program.startTransaction("test");
				try {
					ProgramModule m = listing.getModule("Main Tree", "Strings");

					// create a module
					try {
						m = m.createModule("my new module");
					}
					catch (DuplicateNameException e) {
						Assert.fail("Got duplicate name exception!");
					}

				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		executeMerge();
		// should get "Some Other Tree" and a module called "my new module"
		ProgramModule root = resultProgram.getListing().getRootModule("Some Other Tree");
		assertNotNull(root);
		ProgramModule m = resultProgram.getListing().getModule("Some Other Tree", "my new module");
		assertNotNull(m);
	}

	@Test
	public void testContentNameChanged() throws Exception {
		// Case 3: "other" content changed, "private" name changed
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
					ProgramModule m = listing.getModule("Main Tree", "Strings");
					m.createModule("my new module");
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
				// change my content
				int transactionID = program.startTransaction("test");
				try {
					listing.renameTree("Main Tree", "Some Other Tree");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
		executeMerge();
		// should get "Some Other Tree" and a module called "my new module"
		ProgramModule root = resultProgram.getListing().getRootModule("Some Other Tree");
		assertNotNull(root);
		ProgramModule m = resultProgram.getListing().getModule("Some Other Tree", "my new module");
		assertNotNull(m);
	}
}
