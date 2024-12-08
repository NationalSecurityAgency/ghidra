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

import org.junit.Test;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.util.ProgramDiff;

public class CommentSarifTest extends AbstractSarifTest {

	public CommentSarifTest() {
		super();
	}

	@Test
	public void testComments() throws Exception {
		block.putBytes(entry, asm, 0, asm.length);

		Listing listing = program.getListing();
		listing.setComment(entry.add(1), CodeUnit.EOL_COMMENT, "My EOL comment");
		listing.setComment(entry.add(2), CodeUnit.PRE_COMMENT, "My Pre comment");
		listing.setComment(entry.add(3), CodeUnit.POST_COMMENT, "My Post comment");
		listing.setComment(entry.add(4), CodeUnit.PLATE_COMMENT, "My Plate comment");
		listing.setComment(entry.add(5), CodeUnit.REPEATABLE_COMMENT, "My Repeatable comment");

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
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
		listing.setComment(entry.add(4), CodeUnit.PLATE_COMMENT, "My Plate comment");

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testCommentsNoYouCantDoThis() throws Exception {
		block.putBytes(entry, asm, 0, asm.length);

		Listing listing = program.getListing();
		Structure struct = new StructureDataType("My Struct", 0);
		struct.add(new WordDataType(), "wordName", "wordComment");
		struct.add(new ByteDataType(), "byteName", "byteComment");
		listing.setComment(entry.add(1), CodeUnit.EOL_COMMENT, "My EOL comment");
		listing.createData(entry, struct);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(!differences.isEmpty());
	}
}
