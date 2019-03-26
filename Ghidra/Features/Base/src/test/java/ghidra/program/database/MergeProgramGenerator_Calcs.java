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

public class MergeProgramGenerator_Calcs implements MergeProgramGenerator {

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

	MergeProgramGenerator_Calcs(Object consumer) {
		this.consumer = consumer;
	}

	@Override
	public ProgramDB generateProgram(String programName) throws Exception {
		if ("calc.exe".equals(programName)) {
			return buildCalcExeProgram();
		}
		else if ("overlayCalc".equals(programName)) {
			return buildOverlayCalcExeProgram();
		}
		throw new AssertException("Add new builder for program: " + programName);
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

	private ProgramDB buildOverlayCalcExeProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("calc.exe", ProgramBuilder._TOY, consumer);

		builder.createMemory(".text", "0x1001000", 0x12600);
		builder.createMemory(".data", "0x1014000", 0xc00);
		builder.createMemory(".data", "0x10150bf", 0x4c0);
		builder.createMemory(".rsrc", "0x1018bff", 0x2c00);
		builder.createOverlayMemory("TextOverlay", "0x01001630", 0x200);

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
