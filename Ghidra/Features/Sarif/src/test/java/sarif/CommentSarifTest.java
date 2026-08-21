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
package sarif;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramDiff;

public class CommentSarifTest extends AbstractSarifTest {

	public CommentSarifTest() {
		super();
	}

	@Test
	public void testComments() throws Exception {
		block.putBytes(entry, asm, 0, asm.length);

		Listing listing = program.getListing();
		listing.setComment(entry.add(1), CommentType.EOL, "My EOL comment");
		listing.setComment(entry.add(2), CommentType.PRE, "My Pre comment");
		listing.setComment(entry.add(3), CommentType.POST, "My Post comment");
		listing.setComment(entry.add(4), CommentType.PLATE, "My Plate comment");
		listing.setComment(entry.add(5), CommentType.REPEATABLE, "My Repeatable comment");

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

	@Test
	public void testCommentsInData() throws Exception {
		block.putBytes(entry, asm, 0, asm.length);

		Listing listing = program.getListing();
		Structure struct = new StructureDataType("My Struct", 0);
		Union union = new UnionDataType("My Union");
		ArrayDataType array = new ArrayDataType(new ShortDataType(), 2, 2);
		union.add(array, "shortArrayName", "shortArrayComment");
		union.add(new DWordDataType(), "dwordName", "dwordComment");
		struct.add(new WordDataType(), "wordName", "wordComment");
		struct.add(union, "unionName", "unionComment");
		struct.add(new ByteDataType(), "byteName", "byteComment");
		listing.createData(entry, struct);
		listing.setComment(entry.add(4), CommentType.PLATE, "My Plate comment");

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

	@Test
	public void testCommentsInInstr() throws Exception {
		block.putBytes(entry, asm, 0, asm.length);

		Listing listing = program.getListing();

		DisassembleCommand cmd = new DisassembleCommand(entry, new AddressSet(entry, entry), false);
		assertTrue(cmd.applyTo(program));
		Instruction instr = listing.getInstructionAt(entry);
		assertNotNull(instr);
		listing.setComment(entry, CommentType.EOL, "My EOL comment");

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

	@Test
	public void testCommentsNoYouCantDoThis() throws Exception {
		block.putBytes(entry, asm, 0, asm.length);

		Listing listing = program.getListing();
		Structure struct = new StructureDataType("My Struct", 0);
		struct.add(new WordDataType(), "wordName", "wordComment");
		struct.add(new ByteDataType(), "byteName", "byteComment");
		listing.setComment(entry.add(1), CommentType.EOL, "My EOL comment");
		listing.createData(entry, struct);

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (!differences.isEmpty());
	}
}
