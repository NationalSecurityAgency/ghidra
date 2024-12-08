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

import java.util.Date;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramDiff;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.AssertException;

public class MergeMipsSarifTest extends AbstractSarifTest {

	private UniversalID lastGeneratedUniversalID;
	private Object consumer;


	public MergeMipsSarifTest() {
		super();
	}

	@Test
	public void testMips() throws Exception {
		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	protected Program getProgram(String progName) throws Exception {
		return buildR4000Program();
	}
	
	public void reset() throws Exception {
		if (program != null) {
			if (txIdOut != -1) {
				program.endTransaction(txIdOut, true);
			}
			txIdOut = -1;
		}

		builder = new ProgramBuilder("TestInProgram", ProgramBuilder._MIPS);
		program2 = builder.getProgram();
		program2.addConsumer(this);

		txIdIn = program2.startTransaction("TestIn");
	}
	
	private ProgramDB buildR4000Program() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("r4000", ProgramBuilder._MIPS, consumer);

		builder.createMemory("label", "08000", 0x1000);
		builder.setBytes(
			"808c",
			"0c 10 d0 2b 24 04 00 33 0c 10 7e a4 24 16 00 30 af a2 00 44 40 04 78 00 00 00 00 00 00 04 12 02 30 42 00 ff",
			true);
		builder.setBytes("80b0", "24 03 00 27 14 43 00 0a 30 82 00 ff 2c 42 00 21 14 40 00 07",
			true);
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		ProgramDB program = builder.getProgram();

		AbstractGenericTest.setInstanceField("recordChanges", program, Boolean.TRUE);

		UniversalID ID = UniversalIdGenerator.nextID();

		if (lastGeneratedUniversalID != null) {
			if (!lastGeneratedUniversalID.equals(ID)) {
				// if this happens, update initializeStaticUniversalIDUsage()
				throw new AssertException("Expected Test UniversalID has changed.  "
					+ "This is probably due to an new static usage of the UniversalIDGenerator.");
			}
		}

		return program;
	}
}
