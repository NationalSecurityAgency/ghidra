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

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.listing.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;

/**
 * Test the tree merger and its Use For All checkbox option.
 */
public class ProgramTreeMergeManagerUseForAllTest extends AbstractProgramTreeMergeManagerTest {

	public void setupContentsNamesChangedUseForAllTest() throws Exception {
		// Both contents changed and both names changed
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
					ProgramModule mainRoot = listing.getRootModule("Main Tree");
					mainRoot.createFragment("frag_one");
					mainRoot.createModule("latest module");
					listing.renameTree("Main Tree", "LatestMainTree");

					ProgramModule root3 = listing.getRootModule("Tree Three");
					root3.createFragment("frag_99");
					root3.createModule("latest module 55");
					listing.renameTree("Tree Three", "Latest Tree 3");

					listing.renameTree("Tree Two", "Latest Tree 2");

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
			public void modifyPrivate(ProgramDB program) throws DuplicateGroupException {
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

					ProgramModule moduleB = listing.getModule("Tree Three", "B");
					ProgramFragment textFrag3 = listing.getFragment("Tree Three", ".text");
					moduleB.add(textFrag3);
					listing.renameTree("Tree Three", "My Tree 3");

					listing.renameTree("Tree Two", "My Tree 2");

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
	}

	@Test
	public void testContentsNamesChangedDoNotUseForAllAddMy() throws Exception {
		// Both contents changed and both names changed
		// conflict resolution = KEEP_OTHER_NAME
		setupContentsNamesChangedUseForAllTest();

		merge();

		resolveNameConflictsPanelConflict(
			"Tree named 'LatestMainTree' (Latest) conflicts with 'Another Main Tree' (Checked Out)",
			ProgramTreeMergeManager.ADD_NEW_TREE, false);
		resolveNameConflictsPanelConflict(
			"Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)",
			ProgramTreeMergeManager.ADD_NEW_TREE, false);
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2",
			ProgramTreeMergeManager.KEEP_PRIVATE_NAME, false);

		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNotNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNull(resultListing.getRootModule("Latest Tree 2"));
		assertNotNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNotNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNotNull(resultListing.getModule("LatestMainTree", "latest module"));
		assertNotNull(resultListing.getFragment("LatestMainTree", "frag_one"));
		assertNotNull(resultListing.getModule("Another Main Tree", "my new module"));
		assertNotNull(resultListing.getFragment("Another Main Tree", "my fragment"));
	}

	@Test
	public void testContentsNamesChangedDoNotUseForAllPickLatest() throws Exception {
		// Both contents changed and both names changed
		// conflict resolution = KEEP_OTHER_NAME
		setupContentsNamesChangedUseForAllTest();

		merge();

		resolveNameConflictsPanelConflict(
			"Tree named 'LatestMainTree' (Latest) conflicts with 'Another Main Tree' (Checked Out)",
			ProgramTreeMergeManager.KEEP_OTHER_NAME, false);
		resolveNameConflictsPanelConflict(
			"Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)",
			ProgramTreeMergeManager.KEEP_OTHER_NAME, false);
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2",
			ProgramTreeMergeManager.KEEP_OTHER_NAME, false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNotNull(resultListing.getRootModule("Latest Tree 2"));
		assertNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNotNull(resultListing.getModule("LatestMainTree", "latest module"));
		assertNotNull(resultListing.getFragment("LatestMainTree", "frag_one"));
	}

	@Test
	public void testContentsNamesChangedUseForAllAddMy() throws Exception {
		// Both contents changed and both names changed
		// conflict resolution = KEEP_OTHER_NAME
		setupContentsNamesChangedUseForAllTest();

		merge();

		resolveNameConflictsPanelConflict(
			"Tree named 'LatestMainTree' (Latest) conflicts with 'Another Main Tree' (Checked Out)",
			ProgramTreeMergeManager.ADD_NEW_TREE, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2", ProgramTreeMergeManager.ADD_NEW_TREE,
			false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNotNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNotNull(resultListing.getRootModule("Latest Tree 2"));
		assertNotNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNotNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNotNull(resultListing.getModule("LatestMainTree", "latest module"));
		assertNotNull(resultListing.getFragment("LatestMainTree", "frag_one"));
		assertNotNull(resultListing.getModule("Another Main Tree", "my new module"));
		assertNotNull(resultListing.getFragment("Another Main Tree", "my fragment"));
	}

	@Test
	public void testLatestContentsChangedUseForAllKeepLatest() throws Exception {
		// Only Latest contents changed and both names changed
		// conflict resolution = KEEP_OTHER_NAME
		setupLatestContentsChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.KEEP_OTHER_NAME, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2",
			ProgramTreeMergeManager.KEEP_OTHER_NAME, false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNotNull(resultListing.getRootModule("Latest Tree 2"));
		assertNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNotNull(resultListing.getModule("LatestMainTree", "latest module"));
		assertNotNull(resultListing.getFragment("LatestMainTree", "frag_one"));
	}

	@Test
	public void testLatestContentsChangedUseForAllKeepMy() throws Exception {
		// Only Latest contents changed and both names changed
		// conflict resolution = KEEP_PRIVATE_NAME
		setupLatestContentsChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.KEEP_PRIVATE_NAME, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2",
			ProgramTreeMergeManager.KEEP_PRIVATE_NAME, false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNull(resultListing.getRootModule("LatestMainTree"));
		assertNotNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNull(resultListing.getRootModule("Latest Tree 2"));
		assertNotNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNull(resultListing.getRootModule("Latest Tree 3"));
		assertNotNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNull(resultListing.getModule("LatestMainTree", "latest module"));
		assertNull(resultListing.getFragment("LatestMainTree", "frag_one"));
	}

	@Test
	public void testLatestContentsChangedUseForAllAddMy() throws Exception {
		// Only Latest contents changed and both names changed
		// conflict resolution = ADD_NEW_TREE
		setupLatestContentsChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.ADD_NEW_TREE, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2",
			ProgramTreeMergeManager.KEEP_PRIVATE_NAME, false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNotNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNull(resultListing.getRootModule("Latest Tree 2"));
		assertNotNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNotNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNotNull(resultListing.getModule("LatestMainTree", "latest module"));
		assertNotNull(resultListing.getFragment("LatestMainTree", "frag_one"));
	}

	@Test
	public void testLatestContentsChangedUseForAllKeepOriginal() throws Exception {
		// Only Latest contents changed and both names changed
		// conflict resolution = ORIGINAL_NAME
		setupLatestContentsChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.ORIGINAL_NAME, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2",
			ProgramTreeMergeManager.ORIGINAL_NAME, false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNotNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNotNull(resultListing.getRootModule("Tree Two"));
		assertNull(resultListing.getRootModule("Latest Tree 2"));
		assertNull(resultListing.getRootModule("My Tree 2"));
		assertNotNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNotNull(resultListing.getModule("LatestMainTree", "latest module"));
		assertNotNull(resultListing.getFragment("LatestMainTree", "frag_one"));
	}

	@Test
	public void testMyContentsChangedUseForAllKeepLatest() throws Exception {
		// Only My contents changed and both names changed
		// conflict resolution = KEEP_OTHER_NAME
		setupMyContentsChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.KEEP_OTHER_NAME, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2",
			ProgramTreeMergeManager.KEEP_OTHER_NAME, false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNotNull(resultListing.getRootModule("Latest Tree 2"));
		assertNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNotNull(resultListing.getModule("LatestMainTree", "my new module"));
		assertNotNull(resultListing.getFragment("LatestMainTree", "my fragment"));
		assertNull(resultListing.getModule("Another Main Tree", "my new module"));
		assertNull(resultListing.getFragment("Another Main Tree", "my fragment"));
	}

	@Test
	public void testMyContentsChangedUseForAllKeepMy() throws Exception {
		// Only My contents changed and both names changed
		// conflict resolution = KEEP_PRIVATE_NAME
		setupMyContentsChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.KEEP_PRIVATE_NAME, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2",
			ProgramTreeMergeManager.KEEP_PRIVATE_NAME, false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNull(resultListing.getRootModule("LatestMainTree"));
		assertNotNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNull(resultListing.getRootModule("Latest Tree 2"));
		assertNotNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNull(resultListing.getRootModule("Latest Tree 3"));
		assertNotNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNull(resultListing.getModule("LatestMainTree", "my new module"));
		assertNull(resultListing.getFragment("LatestMainTree", "my fragment"));
		assertNotNull(resultListing.getModule("Another Main Tree", "my new module"));
		assertNotNull(resultListing.getFragment("Another Main Tree", "my fragment"));
	}

	@Test
	public void testMyContentsChangedUseForAllAddMy() throws Exception {
		// Only My contents changed and both names changed
		// conflict resolution = ADD_NEW_TREE
		setupMyContentsChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.ADD_NEW_TREE, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2", ProgramTreeMergeManager.ADD_NEW_TREE,
			false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNotNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNotNull(resultListing.getRootModule("Latest Tree 2"));
		assertNotNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNotNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("Main Tree", "latest module"));
		assertNull(resultListing.getFragment("Main Tree", "frag_one"));
		assertNull(resultListing.getModule("LatestMainTree", "my new module"));
		assertNull(resultListing.getFragment("LatestMainTree", "my fragment"));
		assertNotNull(resultListing.getModule("Another Main Tree", "my new module"));
		assertNotNull(resultListing.getFragment("Another Main Tree", "my fragment"));
	}

	@Test
	public void testMyContentsChangedUseForAllKeepOriginal() throws Exception {
		// Only My contents changed and both names changed
		// conflict resolution = ORIGINAL_NAME
		setupMyContentsChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.ORIGINAL_NAME, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		resolveNamePanelConflict("Latest Tree 2", "My Tree 2",
			ProgramTreeMergeManager.ORIGINAL_NAME, false);
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNotNull(resultListing.getRootModule("Main Tree"));
		assertNull(resultListing.getRootModule("LatestMainTree"));
		assertNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNotNull(resultListing.getRootModule("Tree Two"));
		assertNull(resultListing.getRootModule("Latest Tree 2"));
		assertNull(resultListing.getRootModule("My Tree 2"));
		assertNotNull(resultListing.getRootModule("Tree Three"));
		assertNull(resultListing.getRootModule("Latest Tree 3"));
		assertNull(resultListing.getRootModule("My Tree 3"));

		assertNull(resultListing.getModule("LatestMainTree", "my new module"));
		assertNull(resultListing.getFragment("LatestMainTree", "my fragment"));
		assertNull(resultListing.getModule("Another Main Tree", "my new module"));
		assertNull(resultListing.getFragment("Another Main Tree", "my fragment"));
	}

	@Test
	public void testOnlyNamesChangedUseForAllKeepLatest() throws Exception {
		// Latest and My names changed
		// conflict resolution = KEEP_OTHER_NAME
		setupOnlyNameChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.KEEP_OTHER_NAME, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		// Use For All should handle "Tree named 'Latest Tree 2' (Latest) conflicts with 'My Tree 2' (Checked Out)".
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNotNull(resultListing.getRootModule("Latest Tree 2"));
		assertNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNull(resultListing.getRootModule("My Tree 3"));
	}

	@Test
	public void testOnlyNamesChangedUseForAllKeepMy() throws Exception {
		// Latest and My names changed
		// conflict resolution = KEEP_PRIVATE_NAME
		setupOnlyNameChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.KEEP_PRIVATE_NAME, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		// Use For All should handle "Tree named 'Latest Tree 2' (Latest) conflicts with 'My Tree 2' (Checked Out)".
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNull(resultListing.getRootModule("LatestMainTree"));
		assertNotNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNull(resultListing.getRootModule("Latest Tree 2"));
		assertNotNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNull(resultListing.getRootModule("Latest Tree 3"));
		assertNotNull(resultListing.getRootModule("My Tree 3"));
	}

	@Test
	public void testOnlyNamesChangedUseForAllAddMy() throws Exception {
		// Latest and My names changed
		// conflict resolution = ADD_NEW_TREE
		setupOnlyNameChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.ADD_NEW_TREE, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		// Use For All should handle "Tree named 'Latest Tree 2' (Latest) conflicts with 'My Tree 2' (Checked Out)".
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNull(resultListing.getRootModule("Main Tree"));
		assertNotNull(resultListing.getRootModule("LatestMainTree"));
		assertNotNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNull(resultListing.getRootModule("Tree Two"));
		assertNotNull(resultListing.getRootModule("Latest Tree 2"));
		assertNotNull(resultListing.getRootModule("My Tree 2"));
		assertNull(resultListing.getRootModule("Tree Three"));
		assertNotNull(resultListing.getRootModule("Latest Tree 3"));
		assertNotNull(resultListing.getRootModule("My Tree 3"));
	}

	@Test
	public void testOnlyNamesChangedUseForAllKeepOriginal() throws Exception {
		// Latest and My names changed
		// conflict resolution = ORIGINAL_NAME
		setupOnlyNameChangedUseForAllTest();

		merge();

		resolveNamePanelConflict("LatestMainTree", "Another Main Tree",
			ProgramTreeMergeManager.ORIGINAL_NAME, true);
		// Use For All should handle "Tree named 'Latest Tree 3' (Latest) conflicts with 'My Tree 3' (Checked Out)".
		// Use For All should handle "Tree named 'Latest Tree 2' (Latest) conflicts with 'My Tree 2' (Checked Out)".
		waitForMergeCompletion();

		// Verify results.
		Listing resultListing = resultProgram.getListing();
		assertNotNull(resultListing.getRootModule("Program Tree"));
		assertNotNull(resultListing.getRootModule("Main Tree"));
		assertNull(resultListing.getRootModule("LatestMainTree"));
		assertNull(resultListing.getRootModule("Another Main Tree"));
		assertNotNull(resultListing.getRootModule("Tree One"));
		assertNotNull(resultListing.getRootModule("Tree Two"));
		assertNull(resultListing.getRootModule("Latest Tree 2"));
		assertNull(resultListing.getRootModule("My Tree 2"));
		assertNotNull(resultListing.getRootModule("Tree Three"));
		assertNull(resultListing.getRootModule("Latest Tree 3"));
		assertNull(resultListing.getRootModule("My Tree 3"));
	}

	////////////////////////

	private void setupLatestContentsChangedUseForAllTest() throws Exception {
		// only Latest contents changed and both names changed
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
					ProgramModule mainRoot = listing.getRootModule("Main Tree");
					mainRoot.createFragment("frag_one");
					mainRoot.createModule("latest module");
					listing.renameTree("Main Tree", "LatestMainTree");

					ProgramModule root3 = listing.getRootModule("Tree Three");
					root3.createFragment("frag_99");
					root3.createModule("latest module 55");
					listing.renameTree("Tree Three", "Latest Tree 3");

					listing.renameTree("Tree Two", "Latest Tree 2");

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
			public void modifyPrivate(ProgramDB program) throws DuplicateGroupException {
				boolean commit = false;
				int transactionID = program.startTransaction("test");
				try {
					Listing listing = program.getListing();

					listing.renameTree("Main Tree", "Another Main Tree");

					listing.renameTree("Tree Three", "My Tree 3");

					listing.renameTree("Tree Two", "My Tree 2");

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
	}

	private void setupMyContentsChangedUseForAllTest() throws Exception {
		// only Latest contents changed and both names changed
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
					listing.renameTree("Main Tree", "LatestMainTree");

					listing.renameTree("Tree Three", "Latest Tree 3");

					listing.renameTree("Tree Two", "Latest Tree 2");

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
			public void modifyPrivate(ProgramDB program) throws DuplicateGroupException {
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

					ProgramModule moduleB = listing.getModule("Tree Three", "B");
					ProgramFragment textFrag3 = listing.getFragment("Tree Three", ".text");
					moduleB.add(textFrag3);
					listing.renameTree("Tree Three", "My Tree 3");

					listing.renameTree("Tree Two", "My Tree 2");

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
	}

	private void setupOnlyNameChangedUseForAllTest() throws Exception {
		// only Latest contents changed and both names changed
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
					listing.renameTree("Main Tree", "LatestMainTree");

					listing.renameTree("Tree Three", "Latest Tree 3");

					listing.renameTree("Tree Two", "Latest Tree 2");

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
			public void modifyPrivate(ProgramDB program) throws DuplicateGroupException {
				boolean commit = false;
				int transactionID = program.startTransaction("test");
				try {
					Listing listing = program.getListing();

					listing.renameTree("Main Tree", "Another Main Tree");

					listing.renameTree("Tree Three", "My Tree 3");

					listing.renameTree("Tree Two", "My Tree 2");

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
	}
}
