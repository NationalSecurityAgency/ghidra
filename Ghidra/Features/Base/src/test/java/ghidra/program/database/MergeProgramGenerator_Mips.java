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
package ghidra.program.database;

import java.util.Date;

import generic.test.AbstractGenericTest;
import ghidra.program.model.listing.Program;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.AssertException;

public class MergeProgramGenerator_Mips implements MergeProgramGenerator {

	// this is to detect source code changes that could break our brittle setup
	/**
	 * We keep track of this to know if there are any changes in static initialization.  We want
	 * to make sure that all program building runs result in the same ID sequences.  The first
	 * program built triggers static loading, which will cause the IDs for that run to be 
	 * larger than the subsequent runs.  So, we call all known static initializers before we 
	 * run.  This variable lets us know if a new initializer was added, as the ID value between
	 * the first run and the second run will be different.
	 */
	private UniversalID lastGeneratedUniversalID;

	private Object consumer;

	MergeProgramGenerator_Mips(Object consumer) {
		this.consumer = consumer;
	}

	@Override
	public ProgramDB generateProgram(String programName) throws Exception {
		if ("r4000".equals(programName)) {
			return buildR4000Program();
		}
		throw new AssertException("Add new builder for program: " + programName);
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
