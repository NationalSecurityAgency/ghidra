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
import ghidra.program.model.listing.*;

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

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// don't care
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// don't care
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddSame() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x10028b1"));
		assertEquals("Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddBothSubMyPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
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
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddBothSubMyPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
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
		assertEquals("Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddBothSubMyPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
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
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddBothSubLatestPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddBothSubLatestPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddBothSubLatestPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddDiffPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddDiffPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testAddDiffPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
			cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// don't care
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// don't care
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeBothSame() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();

		CodeUnit cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeBothSubMyPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
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
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeBothSubMyPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
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
		assertEquals("Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeBothSubMyPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
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
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeBothSubLatestPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeBothSubLatestPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeBothSubLatestPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "EOL Comment");
				cu.setComment(CommentType.PRE, "Pre Comment");
				cu.setComment(CommentType.POST, "Post Comment");
				cu.setComment(CommentType.PLATE, "Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeDiffPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeDiffPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));
	}

	@Test
	public void testChangeDiffPickBoth() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
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
			cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CommentType.POST));
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
			cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CommentType.POST));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment" + "\n" + "My Plate Comment",
			cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CommentType.POST));
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
			cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CommentType.POST));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment" + "\n" + "My Plate Comment",
			cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment" + "\n" + "My Pre Comment",
			cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment" + "\n" + "My Post Comment",
			cu.getComment(CommentType.POST));
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
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("Latest Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
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
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("My Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("My EOL Comment", cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("My Post Comment", cu.getComment(CommentType.POST));
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
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CommentType.EOL));
		assertEquals("Latest Repeatable Comment" + "\n" + "My Repeatable Comment",
			cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));

		cu = listing.getCodeUnitAt(addr("0x100230d"));
		assertEquals("Latest Plate Comment", cu.getComment(CommentType.PLATE));
		assertEquals("My Pre Comment", cu.getComment(CommentType.PRE));
		assertEquals("Latest EOL Comment" + "\n" + "My EOL Comment",
			cu.getComment(CommentType.EOL));
		assertEquals("My Repeatable Comment", cu.getComment(CommentType.REPEATABLE));
		assertEquals("Latest Post Comment", cu.getComment(CommentType.POST));
	}

	private void setupAddDiffCommentUseForAll() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");

				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "Latest EOL Comment");
				cu.setComment(CommentType.PRE, "Latest Pre Comment");
				cu.setComment(CommentType.POST, "Latest Post Comment");
				cu.setComment(CommentType.PLATE, "Latest Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "Latest Repeatable Comment");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				Listing listing = program.getListing();
				CodeUnit cu;
				cu = listing.getCodeUnitAt(addr(program, "0x10028b1"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");

				cu = listing.getCodeUnitAt(addr(program, "0x100230d"));
				cu.setComment(CommentType.EOL, "My EOL Comment");
				cu.setComment(CommentType.PRE, "My Pre Comment");
				cu.setComment(CommentType.POST, "My Post Comment");
				cu.setComment(CommentType.PLATE, "My Plate Comment");
				cu.setComment(CommentType.REPEATABLE, "My Repeatable Comment");
			}
		});
	}
}
