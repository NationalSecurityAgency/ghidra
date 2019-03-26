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

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.listing.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class CommentMergeManager2Test extends AbstractListingMergeManagerTest {

	/**
	 * 
	 * @param arg0
	 */
	public CommentMergeManager2Test() {
		super();
	}

@Test
    public void testMergeCommentsLatest() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();

					CodeUnit cu = listing.getCodeUnitAt(addr(program, "0x1001000"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");

					// All comments @ 10028b1
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

					// EOL Comment @ 100283e
					cu = listing.getCodeUnitAt(addr(program, "0x100283e"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");

					// Pre Comment @ 1002840
					cu = listing.getCodeUnitAt(addr(program, "0x1002840"));
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");

					// Post Comment @ 1002843
					cu = listing.getCodeUnitAt(addr(program, "0x1002843"));
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");

					// Plate Comment @ 1002847
					cu = listing.getCodeUnitAt(addr(program, "0x1002847"));
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");

					// Repeatable Comment @ 100284a
					cu = listing.getCodeUnitAt(addr(program, "0x100284a"));
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");

					// All comments @ 10028b1
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
		executeMerge(KEEP_LATEST);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		// EOL Comment @ 100283e
		assertEquals("EOL Comment",
			listing.getCodeUnitAt(addr("0x100283e")).getComment(CodeUnit.EOL_COMMENT));

		// Pre Comment @ 1002840
		assertEquals("Pre Comment",
			listing.getCodeUnitAt(addr("0x1002840")).getComment(CodeUnit.PRE_COMMENT));

		// Post Comment @ 1002843
		assertEquals("Post Comment",
			listing.getCodeUnitAt(addr("0x1002843")).getComment(CodeUnit.POST_COMMENT));

		// Plate Comment @ 1002847
		assertEquals("Plate Comment",
			listing.getCodeUnitAt(addr("0x1002847")).getComment(CodeUnit.PLATE_COMMENT));

		// Repeatable Comment @ 100284a
		assertEquals("Repeatable Comment",
			listing.getCodeUnitAt(addr("0x100284a")).getComment(CodeUnit.REPEATABLE_COMMENT));

		// Latest has comment
		assertEquals("EOL Comment",
			listing.getCodeUnitAt(addr("0x1001000")).getComment(CodeUnit.EOL_COMMENT));

		// Conflicts become latest comments @ 10028b1
		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
	}

@Test
    public void testMergeCommentsMy() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();

					CodeUnit cu = listing.getCodeUnitAt(addr(program, "0x1001000"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");

					// All comments @ 10028b1
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

					// EOL Comment @ 100283e
					cu = listing.getCodeUnitAt(addr(program, "0x100283e"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");

					// Pre Comment @ 1002840
					cu = listing.getCodeUnitAt(addr(program, "0x1002840"));
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");

					// Post Comment @ 1002843
					cu = listing.getCodeUnitAt(addr(program, "0x1002843"));
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");

					// Plate Comment @ 1002847
					cu = listing.getCodeUnitAt(addr(program, "0x1002847"));
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");

					// Repeatable Comment @ 100284a
					cu = listing.getCodeUnitAt(addr(program, "0x100284a"));
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");

					// All comments @ 10028b1
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

		executeMerge(KEEP_MY);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		// EOL Comment @ 100283e
		assertEquals("EOL Comment",
			listing.getCodeUnitAt(addr("0x100283e")).getComment(CodeUnit.EOL_COMMENT));

		// Pre Comment @ 1002840
		assertEquals("Pre Comment",
			listing.getCodeUnitAt(addr("0x1002840")).getComment(CodeUnit.PRE_COMMENT));

		// Post Comment @ 1002843
		assertEquals("Post Comment",
			listing.getCodeUnitAt(addr("0x1002843")).getComment(CodeUnit.POST_COMMENT));

		// Plate Comment @ 1002847
		assertEquals("Plate Comment",
			listing.getCodeUnitAt(addr("0x1002847")).getComment(CodeUnit.PLATE_COMMENT));

		// Repeatable Comment @ 100284a
		assertEquals("Repeatable Comment",
			listing.getCodeUnitAt(addr("0x100284a")).getComment(CodeUnit.REPEATABLE_COMMENT));

		// Latest has comment
		assertEquals("EOL Comment",
			listing.getCodeUnitAt(addr("0x1001000")).getComment(CodeUnit.EOL_COMMENT));

		// Conflicts become my comments @ 10028b1
		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
	}

@Test
    public void testMergeCommentsBoth() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();

					CodeUnit cu = listing.getCodeUnitAt(addr(program, "0x1001000"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");

					// All comments @ 10028b1
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

					// EOL Comment @ 100283e
					cu = listing.getCodeUnitAt(addr(program, "0x100283e"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");

					// Pre Comment @ 1002840
					cu = listing.getCodeUnitAt(addr(program, "0x1002840"));
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");

					// Post Comment @ 1002843
					cu = listing.getCodeUnitAt(addr(program, "0x1002843"));
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");

					// Plate Comment @ 1002847
					cu = listing.getCodeUnitAt(addr(program, "0x1002847"));
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");

					// Repeatable Comment @ 100284a
					cu = listing.getCodeUnitAt(addr(program, "0x100284a"));
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");

					// All comments @ 10028b1
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
		executeMerge(KEEP_BOTH);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		// EOL Comment @ 100283e
		assertEquals(listing.getCodeUnitAt(addr("0x100283e")).getComment(CodeUnit.EOL_COMMENT),
			"EOL Comment");

		// Pre Comment @ 1002840
		assertEquals(listing.getCodeUnitAt(addr("0x1002840")).getComment(CodeUnit.PRE_COMMENT),
			"Pre Comment");

		// Post Comment @ 1002843
		assertEquals(listing.getCodeUnitAt(addr("0x1002843")).getComment(CodeUnit.POST_COMMENT),
			"Post Comment");

		// Plate Comment @ 1002847
		assertEquals(listing.getCodeUnitAt(addr("0x1002847")).getComment(CodeUnit.PLATE_COMMENT),
			"Plate Comment");

		// Repeatable Comment @ 100284a
		assertEquals(
			listing.getCodeUnitAt(addr("0x100284a")).getComment(CodeUnit.REPEATABLE_COMMENT),
			"Repeatable Comment");

		// Latest has comment
		assertEquals(listing.getCodeUnitAt(addr("0x1001000")).getComment(CodeUnit.EOL_COMMENT),
			"EOL Comment");

		// Conflicts become combined comments @ 10028b1
		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CodeUnit.POST_COMMENT));
		assertEquals("Latest Plate Comment" + "\n" + "My Plate Comment",
			cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
	}

@Test
    public void testMergeCommentsAskUser() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();

					CodeUnit cu = listing.getCodeUnitAt(addr(program, "0x1001000"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");

					// All comments @ 10028b1
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

					// EOL Comment @ 100283e
					cu = listing.getCodeUnitAt(addr(program, "0x100283e"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");

					// Pre Comment @ 1002840
					cu = listing.getCodeUnitAt(addr(program, "0x1002840"));
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");

					// Post Comment @ 1002843
					cu = listing.getCodeUnitAt(addr(program, "0x1002843"));
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");

					// Plate Comment @ 1002847
					cu = listing.getCodeUnitAt(addr(program, "0x1002847"));
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");

					// Repeatable Comment @ 100284a
					cu = listing.getCodeUnitAt(addr(program, "0x100284a"));
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");

					// All comments @ 10028b1
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
		chooseComment("Plate", addr("0x10028b1"), KEEP_LATEST); // Plate @ 0x10028b1
		chooseComment("Pre", addr("0x10028b1"), KEEP_MY); // Pre @ 0x10028b1
		chooseComment("Eol", addr("0x10028b1"), KEEP_BOTH); // Eol @ 0x10028b1
		chooseComment("Repeatable", addr("0x10028b1"), KEEP_LATEST); // Repeatable @ 0x10028b1
		chooseComment("Post", addr("0x10028b1"), KEEP_MY); // Post @ 0x10028b1
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		// EOL Comment @ 100283e
		assertEquals(listing.getCodeUnitAt(addr("0x100283e")).getComment(CodeUnit.EOL_COMMENT),
			"EOL Comment");

		// Pre Comment @ 1002840
		assertEquals(listing.getCodeUnitAt(addr("0x1002840")).getComment(CodeUnit.PRE_COMMENT),
			"Pre Comment");

		// Post Comment @ 1002843
		assertEquals(listing.getCodeUnitAt(addr("0x1002843")).getComment(CodeUnit.POST_COMMENT),
			"Post Comment");

		// Plate Comment @ 1002847
		assertEquals(listing.getCodeUnitAt(addr("0x1002847")).getComment(CodeUnit.PLATE_COMMENT),
			"Plate Comment");

		// Repeatable Comment @ 100284a
		assertEquals(
			listing.getCodeUnitAt(addr("0x100284a")).getComment(CodeUnit.REPEATABLE_COMMENT),
			"Repeatable Comment");

		// Latest has comment
		assertEquals(listing.getCodeUnitAt(addr("0x1001000")).getComment(CodeUnit.EOL_COMMENT),
			"EOL Comment");

		// Conflicts become latest comments @ 10028b1
		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

@Test
    public void testDeleteMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
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
					cu.setComment(CodeUnit.EOL_COMMENT, null);
					cu.setComment(CodeUnit.PRE_COMMENT, null);
					cu.setComment(CodeUnit.POST_COMMENT, null);
					cu.setComment(CodeUnit.PLATE_COMMENT, null);
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
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
		assertNull(cu.getComment(CodeUnit.PLATE_COMMENT));
		assertNull(cu.getComment(CodeUnit.PRE_COMMENT));
		assertNull(cu.getComment(CodeUnit.EOL_COMMENT));
		assertNull(cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertNull(cu.getComment(CodeUnit.POST_COMMENT));
	}

@Test
    public void testDeleteLatest() throws Exception {
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
					cu.setComment(CodeUnit.EOL_COMMENT, null);
					cu.setComment(CodeUnit.PRE_COMMENT, null);
					cu.setComment(CodeUnit.POST_COMMENT, null);
					cu.setComment(CodeUnit.PLATE_COMMENT, null);
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
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
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertNull(cu.getComment(CodeUnit.PLATE_COMMENT));
		assertNull(cu.getComment(CodeUnit.PRE_COMMENT));
		assertNull(cu.getComment(CodeUnit.EOL_COMMENT));
		assertNull(cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertNull(cu.getComment(CodeUnit.POST_COMMENT));
	}

@Test
    public void testDeleteBoth() throws Exception {
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
					cu.setComment(CodeUnit.EOL_COMMENT, null);
					cu.setComment(CodeUnit.PRE_COMMENT, null);
					cu.setComment(CodeUnit.POST_COMMENT, null);
					cu.setComment(CodeUnit.PLATE_COMMENT, null);
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
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
					cu.setComment(CodeUnit.EOL_COMMENT, null);
					cu.setComment(CodeUnit.PRE_COMMENT, null);
					cu.setComment(CodeUnit.POST_COMMENT, null);
					cu.setComment(CodeUnit.PLATE_COMMENT, null);
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
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
		assertNull(cu.getComment(CodeUnit.PLATE_COMMENT));
		assertNull(cu.getComment(CodeUnit.PRE_COMMENT));
		assertNull(cu.getComment(CodeUnit.EOL_COMMENT));
		assertNull(cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertNull(cu.getComment(CodeUnit.POST_COMMENT));
	}

@Test
    public void testChangeLatestDeleteMyPickLatest() throws Exception {
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
					cu.setComment(CodeUnit.EOL_COMMENT, null);
					cu.setComment(CodeUnit.PRE_COMMENT, null);
					cu.setComment(CodeUnit.POST_COMMENT, null);
					cu.setComment(CodeUnit.PLATE_COMMENT, null);
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
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
    public void testChangeLatestDeleteMyPickMy() throws Exception {
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
					cu.setComment(CodeUnit.EOL_COMMENT, null);
					cu.setComment(CodeUnit.PRE_COMMENT, null);
					cu.setComment(CodeUnit.POST_COMMENT, null);
					cu.setComment(CodeUnit.PLATE_COMMENT, null);
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
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
		assertNull(cu.getComment(CodeUnit.PLATE_COMMENT));
		assertNull(cu.getComment(CodeUnit.PRE_COMMENT));
		assertNull(cu.getComment(CodeUnit.EOL_COMMENT));
		assertNull(cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertNull(cu.getComment(CodeUnit.POST_COMMENT));
	}

@Test
    public void testChangeMyDeleteLatestPickLatest() throws Exception {
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
					cu.setComment(CodeUnit.EOL_COMMENT, null);
					cu.setComment(CodeUnit.PRE_COMMENT, null);
					cu.setComment(CodeUnit.POST_COMMENT, null);
					cu.setComment(CodeUnit.PLATE_COMMENT, null);
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
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
		assertNull(cu.getComment(CodeUnit.PLATE_COMMENT));
		assertNull(cu.getComment(CodeUnit.PRE_COMMENT));
		assertNull(cu.getComment(CodeUnit.EOL_COMMENT));
		assertNull(cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertNull(cu.getComment(CodeUnit.POST_COMMENT));
	}

@Test
    public void testChangeMyDeleteLatestPickMy() throws Exception {
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
					cu.setComment(CodeUnit.EOL_COMMENT, null);
					cu.setComment(CodeUnit.PRE_COMMENT, null);
					cu.setComment(CodeUnit.POST_COMMENT, null);
					cu.setComment(CodeUnit.PLATE_COMMENT, null);
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
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
    public void testAddUnInitNoConflict() throws Exception {
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
					cu = listing.getCodeUnitAt(addr(program, "0x1008606"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					cu = listing.getCodeUnitAt(addr(program, "0x1008607"));
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
					cu = listing.getCodeUnitAt(addr(program, "0x1008607"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable Comment");
					cu = listing.getCodeUnitAt(addr(program, "0x1008608"));
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

		CodeUnit cu = listing.getCodeUnitAt(addr("0x1008606"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
		cu = listing.getCodeUnitAt(addr("0x1008607"));
		assertEquals("Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
		cu = listing.getCodeUnitAt(addr("0x1008608"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

@Test
    public void testAddUnInitWithConflict() throws Exception {
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
					cu = listing.getCodeUnitAt(addr(program, "0x1008606"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					cu = listing.getCodeUnitAt(addr(program, "0x1008607"));
					cu.setComment(CodeUnit.EOL_COMMENT, "Latest EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "Latest Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "Latest Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Latest Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Latest Repeatable Comment");
					cu = listing.getCodeUnitAt(addr(program, "0x1008608"));
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
					cu = listing.getCodeUnitAt(addr(program, "0x1008606"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					cu = listing.getCodeUnitAt(addr(program, "0x1008607"));
					cu.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
					cu.setComment(CodeUnit.PRE_COMMENT, "My Pre Comment");
					cu.setComment(CodeUnit.POST_COMMENT, "My Post Comment");
					cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "My Repeatable Comment");
					cu = listing.getCodeUnitAt(addr(program, "0x1008608"));
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

		chooseComment("Latest Plate Comment", addr("0x1008606"), KEEP_LATEST);
		chooseComment("Latest Pre Comment", addr("0x1008606"), KEEP_LATEST);
		chooseComment("Latest Eol Comment", addr("0x1008606"), KEEP_LATEST);
		chooseComment("Latest Repeatable Comment", addr("0x1008606"), KEEP_LATEST);
		chooseComment("Latest Post Comment", addr("0x1008606"), KEEP_LATEST);

		chooseComment("My Plate Comment", addr("0x1008607"), KEEP_MY);
		chooseComment("My Pre Comment", addr("0x1008607"), KEEP_MY);
		chooseComment("My Eol Comment", addr("0x1008607"), KEEP_MY);
		chooseComment("My Repeatable Comment", addr("0x1008607"), KEEP_MY);
		chooseComment("My Post Comment", addr("0x1008607"), KEEP_MY);

		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX, MY_CHECK_BOX }); // Plate
		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX, MY_CHECK_BOX }); // Pre
		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX, MY_CHECK_BOX }); // EOL
		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX, MY_CHECK_BOX }); // Repeatable
		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX, MY_CHECK_BOX }); // Post

		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x1008606"));
		assertEquals("Latest Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
		cu = listing.getCodeUnitAt(addr("0x1008607"));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("My EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("My Repeatable Comment", cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("My Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
		cu = listing.getCodeUnitAt(addr("0x1008608"));
		assertEquals("Latest Plate Comment\nMy Plate Comment",
			cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("Latest Pre Comment\nMy Pre Comment", cu.getComment(CodeUnit.PRE_COMMENT));
		assertEquals("Latest EOL Comment\nMy EOL Comment", cu.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Latest Repeatable Comment\nMy Repeatable Comment",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
		assertEquals("Latest Post Comment\nMy Post Comment", cu.getComment(CodeUnit.POST_COMMENT));
	}

@Test
    public void testAddCommentInsideCodeUnit() throws Exception {
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
					cu = listing.getCodeUnitAt(addr(program, "0x10065e3"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre");
					cu.setComment(CodeUnit.POST_COMMENT, "Post");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable");

					createData(program, "0x10065e8", new DWordDataType());

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
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10065e2", new FloatDataType());

					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x10065e9"));
					cu.setComment(CodeUnit.EOL_COMMENT, "EOL2");
					cu.setComment(CodeUnit.PRE_COMMENT, "Pre2");
					cu.setComment(CodeUnit.POST_COMMENT, "Post2");
					cu.setComment(CodeUnit.PLATE_COMMENT, "Plate2");
					cu.setComment(CodeUnit.REPEATABLE_COMMENT, "Repeatable2");

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

		CodeUnit cu;
		cu = listing.getCodeUnitContaining(addr("0x10065e3"));
		assertEquals(addr("0x10065e2"), cu.getMinAddress());
		assertEquals(4, cu.getLength());
		assertTrue(((Data) cu).getDataType().isEquivalent(new FloatDataType()));
		assertEquals("EOL", listing.getComment(CodeUnit.EOL_COMMENT, addr("0x10065e3")));
		assertEquals("Pre", listing.getComment(CodeUnit.PRE_COMMENT, addr("0x10065e3")));
		assertEquals("Post", listing.getComment(CodeUnit.POST_COMMENT, addr("0x10065e3")));
		assertEquals("Plate", listing.getComment(CodeUnit.PLATE_COMMENT, addr("0x10065e3")));
		assertEquals("Repeatable",
			listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr("0x10065e3")));

		cu = listing.getCodeUnitContaining(addr("0x10065e9"));
		assertEquals(addr("0x10065e8"), cu.getMinAddress());
		assertEquals(4, cu.getLength());
		assertTrue(((Data) cu).getDataType().isEquivalent(new DWordDataType()));
		assertEquals("EOL2", listing.getComment(CodeUnit.EOL_COMMENT, addr("0x10065e9")));
		assertEquals("Pre2", listing.getComment(CodeUnit.PRE_COMMENT, addr("0x10065e9")));
		assertEquals("Post2", listing.getComment(CodeUnit.POST_COMMENT, addr("0x10065e9")));
		assertEquals("Plate2", listing.getComment(CodeUnit.PLATE_COMMENT, addr("0x10065e9")));
		assertEquals("Repeatable2",
			listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr("0x10065e9")));
	}

@Test
    public void testChangeLatestCommentInsideMyCodeUnit() throws Exception {
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
					listing.setComment(addr(program, "0x1002040"), CodeUnit.EOL_COMMENT,
						"New EOL Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PRE_COMMENT,
						"New Pre Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.POST_COMMENT,
						"New Post Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PLATE_COMMENT,
						"New Plate Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.REPEATABLE_COMMENT,
						"New Repeatable Comment");
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
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program,
						new AddressSet(addr(program, "0x100203e"), addr(program, "0x1002043")),
						false);
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

		CodeUnit cu;
		cu = listing.getCodeUnitContaining(addr("0x1002040"));
		assertEquals(addr("0x100203f"), cu.getMinAddress());
		assertEquals(2, cu.getLength());
		assertTrue(cu instanceof Instruction);
		assertEquals("New EOL Comment", listing.getComment(CodeUnit.EOL_COMMENT, addr("0x1002040")));
		assertEquals("New Pre Comment", listing.getComment(CodeUnit.PRE_COMMENT, addr("0x1002040")));
		assertEquals("New Post Comment",
			listing.getComment(CodeUnit.POST_COMMENT, addr("0x1002040")));
		assertEquals("New Plate Comment",
			listing.getComment(CodeUnit.PLATE_COMMENT, addr("0x1002040")));
		assertEquals("New Repeatable Comment",
			listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr("0x1002040")));
	}

@Test
    public void testChangeMyCommentInsideLatestCodeUnit() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program,
						new AddressSet(addr(program, "0x100203e"), addr(program, "0x1002043")),
						false);
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
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.setComment(addr(program, "0x1002040"), CodeUnit.EOL_COMMENT,
						"New EOL Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PRE_COMMENT,
						"New Pre Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.POST_COMMENT,
						"New Post Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PLATE_COMMENT,
						"New Plate Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.REPEATABLE_COMMENT,
						"New Repeatable Comment");
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

		CodeUnit cu;
		cu = listing.getCodeUnitContaining(addr("0x1002040"));
		assertEquals(addr("0x100203f"), cu.getMinAddress());
		assertEquals(2, cu.getLength());
		assertTrue(cu instanceof Instruction);
		assertEquals("New EOL Comment", listing.getComment(CodeUnit.EOL_COMMENT, addr("0x1002040")));
		assertEquals("New Pre Comment", listing.getComment(CodeUnit.PRE_COMMENT, addr("0x1002040")));
		assertEquals("New Post Comment",
			listing.getComment(CodeUnit.POST_COMMENT, addr("0x1002040")));
		assertEquals("New Plate Comment",
			listing.getComment(CodeUnit.PLATE_COMMENT, addr("0x1002040")));
		assertEquals("New Repeatable Comment",
			listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr("0x1002040")));
	}

@Test
    public void testRemoveCommentInsideMyCodeUnit() throws Exception {
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
					listing.setComment(addr(program, "0x1002040"), CodeUnit.EOL_COMMENT, null);
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
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PRE_COMMENT, null);
					disassemble(program,
						new AddressSet(addr(program, "0x100203e"), addr(program, "0x1002043")),
						false);
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

		CodeUnit cu;
		cu = listing.getCodeUnitContaining(addr("0x1002040"));
		assertEquals(addr("0x100203f"), cu.getMinAddress());
		assertEquals(2, cu.getLength());
		assertTrue(cu instanceof Instruction);
		assertNull(listing.getComment(CodeUnit.EOL_COMMENT, addr("0x1002040")));
		assertNull(listing.getComment(CodeUnit.PRE_COMMENT, addr("0x1002040")));
		assertEquals("Post in P1.", listing.getComment(CodeUnit.POST_COMMENT, addr("0x1002040")));
		assertEquals("Plate in P1.", listing.getComment(CodeUnit.PLATE_COMMENT, addr("0x1002040")));
		assertEquals("Repeatable in P1.",
			listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr("0x1002040")));
	}

@Test
    public void testRemoveCommentInsideLatestCodeUnit() throws Exception {
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
					listing.setComment(addr(program, "0x1002040"), CodeUnit.POST_COMMENT, null);
					disassemble(program,
						new AddressSet(addr(program, "0x100203e"), addr(program, "0x1002043")),
						false);
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
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PLATE_COMMENT, null);
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

		CodeUnit cu;
		cu = listing.getCodeUnitContaining(addr("0x1002040"));
		assertEquals(addr("0x100203f"), cu.getMinAddress());
		assertEquals(2, cu.getLength());
		assertTrue(cu instanceof Instruction);
		assertEquals("EOL in P1.", listing.getComment(CodeUnit.EOL_COMMENT, addr("0x1002040")));
		assertEquals("Pre in P1.", listing.getComment(CodeUnit.PRE_COMMENT, addr("0x1002040")));
		assertNull(listing.getComment(CodeUnit.POST_COMMENT, addr("0x1002040")));
		assertNull(listing.getComment(CodeUnit.PLATE_COMMENT, addr("0x1002040")));
		assertEquals("Repeatable in P1.",
			listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr("0x1002040")));
	}

@Test
    public void testChangeCommentInsideMyCodeUnit() throws Exception {
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
					listing.setComment(addr(program, "0x1002040"), CodeUnit.EOL_COMMENT,
						"Latest EOL Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PRE_COMMENT,
						"Latest Pre Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.POST_COMMENT,
						"Latest Post Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PLATE_COMMENT,
						"New Plate Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.REPEATABLE_COMMENT,
						"New Repeatable Comment");
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
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.setComment(addr(program, "0x1002040"), CodeUnit.EOL_COMMENT,
						"My EOL Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PRE_COMMENT,
						"My Pre Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.POST_COMMENT,
						"My Post Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PLATE_COMMENT,
						"New Plate Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.REPEATABLE_COMMENT,
						"New Repeatable Comment");
					disassemble(program,
						new AddressSet(addr(program, "0x100203e"), addr(program, "0x1002043")),
						false);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX_NAME }); // Pre
		chooseVerticalCheckBoxes(new String[] { CHECKED_OUT_CHECK_BOX_NAME }); // EOL
		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX_NAME, CHECKED_OUT_CHECK_BOX_NAME }); // Post
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu;
		cu = listing.getCodeUnitContaining(addr("0x1002040"));
		assertEquals(addr("0x100203f"), cu.getMinAddress());
		assertEquals(2, cu.getLength());
		assertTrue(cu instanceof Instruction);
		assertEquals("My EOL Comment", listing.getComment(CodeUnit.EOL_COMMENT, addr("0x1002040")));
		assertEquals("Latest Pre Comment",
			listing.getComment(CodeUnit.PRE_COMMENT, addr("0x1002040")));
		assertEquals("Latest Post Comment\nMy Post Comment",
			listing.getComment(CodeUnit.POST_COMMENT, addr("0x1002040")));
		assertEquals("New Plate Comment",
			listing.getComment(CodeUnit.PLATE_COMMENT, addr("0x1002040")));
		assertEquals("New Repeatable Comment",
			listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr("0x1002040")));
	}

@Test
    public void testChangeCommentInsideLatestCodeUnit() throws Exception {
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
					disassemble(program,
						new AddressSet(addr(program, "0x100203e"), addr(program, "0x1002043")),
						false);
					listing.setComment(addr(program, "0x1002040"), CodeUnit.EOL_COMMENT,
						"New EOL Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PRE_COMMENT,
						"New Pre Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.POST_COMMENT,
						"Latest Post Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PLATE_COMMENT,
						"Latest Plate Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.REPEATABLE_COMMENT,
						"Latest Repeatable Comment");
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
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.setComment(addr(program, "0x1002040"), CodeUnit.EOL_COMMENT,
						"New EOL Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PRE_COMMENT,
						"New Pre Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.POST_COMMENT,
						"My Post Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.PLATE_COMMENT,
						"My Plate Comment");
					listing.setComment(addr(program, "0x1002040"), CodeUnit.REPEATABLE_COMMENT,
						"My Repeatable Comment");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX_NAME }); // Plate
		chooseVerticalCheckBoxes(new String[] { CHECKED_OUT_CHECK_BOX_NAME }); // Repeatable
		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX_NAME, CHECKED_OUT_CHECK_BOX_NAME }); // Post
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu;
		cu = listing.getCodeUnitContaining(addr("0x1002040"));
		assertEquals(addr("0x100203f"), cu.getMinAddress());
		assertEquals(2, cu.getLength());
		assertTrue(cu instanceof Instruction);
		assertEquals("New EOL Comment", listing.getComment(CodeUnit.EOL_COMMENT, addr("0x1002040")));
		assertEquals("New Pre Comment", listing.getComment(CodeUnit.PRE_COMMENT, addr("0x1002040")));
		assertEquals("Latest Post Comment\nMy Post Comment",
			listing.getComment(CodeUnit.POST_COMMENT, addr("0x1002040")));
		assertEquals("Latest Plate Comment",
			listing.getComment(CodeUnit.PLATE_COMMENT, addr("0x1002040")));
		assertEquals("My Repeatable Comment",
			listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr("0x1002040")));
	}

}
