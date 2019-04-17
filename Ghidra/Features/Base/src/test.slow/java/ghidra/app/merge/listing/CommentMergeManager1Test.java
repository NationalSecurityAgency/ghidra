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
package ghidra.app.merge.listing;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;

/**
 * Test the merge of the versioned program's listing.
 */
public class CommentMergeManager1Test extends AbstractListingMergeManagerTest {

	/**
	 * 
	 * @param arg0
	 */
	public CommentMergeManager1Test() {
		super();
	}

	@Test
	public void testAddLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// don't care
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// don't care
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddSame() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddBothSubMyPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Pre", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Eol", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Post", addr("0x10028b1"), KEEP_LATEST);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddBothSubMyPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x10028b1"), KEEP_MY);
		chooseComment("Pre", addr("0x10028b1"), KEEP_MY);
		chooseComment("Eol", addr("0x10028b1"), KEEP_MY);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_MY);
		chooseComment("Post", addr("0x10028b1"), KEEP_MY);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddBothSubMyPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Pre", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Eol", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Post", addr("0x10028b1"), KEEP_BOTH);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddBothSubLatestPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Pre", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Eol", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Post", addr("0x10028b1"), KEEP_LATEST);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddBothSubLatestPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x10028b1"), KEEP_MY);
		chooseComment("Pre", addr("0x10028b1"), KEEP_MY);
		chooseComment("Eol", addr("0x10028b1"), KEEP_MY);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_MY);
		chooseComment("Post", addr("0x10028b1"), KEEP_MY);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddBothSubLatestPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Pre", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Eol", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Post", addr("0x10028b1"), KEEP_BOTH);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddDiffPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Pre", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Eol", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_LATEST);
		chooseComment("Post", addr("0x10028b1"), KEEP_LATEST);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddDiffPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x10028b1"), KEEP_MY);
		chooseComment("Pre", addr("0x10028b1"), KEEP_MY);
		chooseComment("Eol", addr("0x10028b1"), KEEP_MY);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_MY);
		chooseComment("Post", addr("0x10028b1"), KEEP_MY);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddDiffPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Pre", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Eol", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_BOTH);
		chooseComment("Post", addr("0x10028b1"), KEEP_BOTH);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment" + "\n" + "My Plate Comment",
			cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// don't care
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// don't care
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeBothSame() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeBothSubMyPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Pre", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Eol", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Post", addr("0x100230d"), KEEP_LATEST);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeBothSubMyPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x100230d"), KEEP_MY);
		chooseComment("Pre", addr("0x100230d"), KEEP_MY);
		chooseComment("Eol", addr("0x100230d"), KEEP_MY);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_MY);
		chooseComment("Post", addr("0x100230d"), KEEP_MY);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeBothSubMyPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Pre", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Eol", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Post", addr("0x100230d"), KEEP_BOTH);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeBothSubLatestPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Pre", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Eol", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Post", addr("0x100230d"), KEEP_LATEST);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeBothSubLatestPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x100230d"), KEEP_MY);
		chooseComment("Pre", addr("0x100230d"), KEEP_MY);
		chooseComment("Eol", addr("0x100230d"), KEEP_MY);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_MY);
		chooseComment("Post", addr("0x100230d"), KEEP_MY);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeBothSubLatestPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Pre", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Eol", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Post", addr("0x100230d"), KEEP_BOTH);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeDiffPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Pre", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Eol", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_LATEST);
		chooseComment("Post", addr("0x100230d"), KEEP_LATEST);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeDiffPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x100230d"), KEEP_MY);
		chooseComment("Pre", addr("0x100230d"), KEEP_MY);
		chooseComment("Eol", addr("0x100230d"), KEEP_MY);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_MY);
		chooseComment("Post", addr("0x100230d"), KEEP_MY);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testChangeDiffPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseComment("Plate", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Pre", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Eol", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_BOTH);
		chooseComment("Post", addr("0x100230d"), KEEP_BOTH);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment" + "\n" + "My Plate Comment",
			cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddDiffDoNotUseForAllPickBoth() throws Exception {
		setupAddDiffCommentUseForAll();

		executeMerge(ASK_USER);

		chooseComment("Plate", addr("0x100230d"), KEEP_BOTH, false);
		chooseComment("Pre", addr("0x100230d"), KEEP_BOTH, false);
		chooseComment("Eol", addr("0x100230d"), KEEP_BOTH, false);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_BOTH, false);
		chooseComment("Post", addr("0x100230d"), KEEP_BOTH, false);

		chooseComment("Plate", addr("0x10028b1"), KEEP_BOTH, false);
		chooseComment("Pre", addr("0x10028b1"), KEEP_BOTH, false);
		chooseComment("Eol", addr("0x10028b1"), KEEP_BOTH, false);
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_BOTH, false);
		chooseComment("Post", addr("0x10028b1"), KEEP_BOTH, false);

		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment" + "\n" + "My Plate Comment",
			cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CodeUnit.POST_COMMENT));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment" + "\n" + "My Plate Comment",
			cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddDiffUseForAllPickBoth() throws Exception {
		setupAddDiffCommentUseForAll();

		executeMerge(ASK_USER);

		chooseComment("Plate", addr("0x100230d"), KEEP_BOTH, true);
		chooseComment("Pre", addr("0x100230d"), KEEP_BOTH, true);
		chooseComment("Eol", addr("0x100230d"), KEEP_BOTH, true);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_BOTH, true);
		chooseComment("Post", addr("0x100230d"), KEEP_BOTH, true);

//		chooseComment("Plate", addr("0x10028b1"), KEEP_BOTH, false); // UseForAll will do this.
//		chooseComment("Pre", addr("0x10028b1"), KEEP_BOTH, false); // UseForAll will do this.
//		chooseComment("Eol", addr("0x10028b1"), KEEP_BOTH, false); // UseForAll will do this.
//		chooseComment("Repeatable", addr("0x10028b1"), KEEP_BOTH, false); // UseForAll will do this.
//		chooseComment("Post", addr("0x10028b1"), KEEP_BOTH, false); // UseForAll will do this.

		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment" + "\n" + "My Plate Comment",
			cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CodeUnit.POST_COMMENT));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment" + "\n" + "My Plate Comment",
			cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddDiffUseForAllPickLatest() throws Exception {
		setupAddDiffCommentUseForAll();

		executeMerge(ASK_USER);

		chooseComment("Plate", addr("0x100230d"), KEEP_LATEST, true);
		chooseComment("Pre", addr("0x100230d"), KEEP_LATEST, true);
		chooseComment("Eol", addr("0x100230d"), KEEP_LATEST, true);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_LATEST, true);
		chooseComment("Post", addr("0x100230d"), KEEP_LATEST, true);

//		chooseComment("Plate", addr("0x10028b1"), KEEP_LATEST, false); // UseForAll will do this.
//		chooseComment("Pre", addr("0x10028b1"), KEEP_LATEST, false); // UseForAll will do this.
//		chooseComment("Eol", addr("0x10028b1"), KEEP_LATEST, false); // UseForAll will do this.
//		chooseComment("Repeatable", addr("0x10028b1"), KEEP_LATEST, false); // UseForAll will do this.
//		chooseComment("Post", addr("0x10028b1"), KEEP_LATEST, false); // UseForAll will do this.

		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddDiffUseForAllPickMine() throws Exception {
		setupAddDiffCommentUseForAll();

		executeMerge(ASK_USER);

		chooseComment("Plate", addr("0x100230d"), KEEP_MY, true);
		chooseComment("Pre", addr("0x100230d"), KEEP_MY, true);
		chooseComment("Eol", addr("0x100230d"), KEEP_MY, true);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_MY, true);
		chooseComment("Post", addr("0x100230d"), KEEP_MY, true);

//		chooseComment("Plate", addr("0x10028b1"), KEEP_MY, false); // UseForAll will do this.
//		chooseComment("Pre", addr("0x10028b1"), KEEP_MY, false); // UseForAll will do this.
//		chooseComment("Eol", addr("0x10028b1"), KEEP_MY, false); // UseForAll will do this.
//		chooseComment("Repeatable", addr("0x10028b1"), KEEP_MY, false); // UseForAll will do this.
//		chooseComment("Post", addr("0x10028b1"), KEEP_MY, false); // UseForAll will do this.

		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	@Test
	public void testAddDiffUseForAllPickVarious() throws Exception {
		setupAddDiffCommentUseForAll();

		executeMerge(ASK_USER);

		chooseComment("Plate", addr("0x100230d"), KEEP_LATEST, true);
		chooseComment("Pre", addr("0x100230d"), KEEP_MY, true);
		chooseComment("Eol", addr("0x100230d"), KEEP_BOTH, true);
		chooseComment("Repeatable", addr("0x100230d"), KEEP_MY, false);
		chooseComment("Post", addr("0x100230d"), KEEP_LATEST, true);

//		chooseComment("Plate", addr("0x10028b1"), KEEP_BOTH, false); // UseForAll will do this.
//		chooseComment("Pre", addr("0x10028b1"), KEEP_BOTH, false); // UseForAll will do this.
//		chooseComment("Eol", addr("0x10028b1"), KEEP_BOTH, false); // UseForAll will do this.
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_BOTH, false);
//		chooseComment("Post", addr("0x10028b1"), KEEP_BOTH, false); // UseForAll will do this.

		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

	private void setupAddDiffCommentUseForAll() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");

					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");

					cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}
}
