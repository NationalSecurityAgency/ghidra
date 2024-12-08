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

public class MergeCalcSarifTest extends AbstractSarifTest {

	private UniversalID lastGeneratedUniversalID;
	private Object consumer;


	public MergeCalcSarifTest() {
		super();
	}

	@Test
	public void testCalc() throws Exception {
		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	protected Program getProgram(String progName) throws Exception {
		return buildCalcExeProgram();
	}
	
	private ProgramDB buildCalcExeProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("calc.exe", ProgramBuilder._TOY, consumer);

		builder.createMemory(".text", "0x1001000", 0x12600);
		builder.createMemory(".data", "0x1014000", 0xc00);
		builder.createMemory(".data", "0x10150bf", 0x4c0);
		builder.createMemory(".rsrc", "0x1018bff", 0x2c00);

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
