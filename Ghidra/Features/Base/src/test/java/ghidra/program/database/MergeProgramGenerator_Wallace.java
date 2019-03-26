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
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.AssertException;

class MergeProgramGenerator_Wallace implements MergeProgramGenerator {

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

	MergeProgramGenerator_Wallace(Object consumer) {
		this.consumer = consumer;
	}

	@Override
	public ProgramDB generateProgram(String programName) throws Exception {

		if ("WallaceSrc".equals(programName)) {
			return buildWallaceSrcProgram();
		}
		throw new AssertException("Add new builder for program: " + programName);
	}

	private ProgramDB buildWallaceSrcProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("wallaceSrc", ProgramBuilder._X86, consumer);

		builder.createMemory(".text", "0x401000", 0xc00);
		builder.createMemory(".rdata", "0x402000", 0x800);
		builder.createMemory(".data", "0x403000", 0x200);
		builder.createMemory(".data", "0x403200", 0x190);
		Program program = builder.getProgram();
		DataType dt = new PointerDataType();
		Parameter p1 = new ParameterImpl(null, dt, program);
		Parameter p_list = new ParameterImpl("list", dt, program);
		Parameter p_personName = new ParameterImpl("personName", dt, program);

		builder.createEmptyFunction("deplayGadget", "4011f0", 204, null);
		builder.createEmptyFunction("Gadget", "401000", 48, null, p1);
		builder.createEmptyFunction("use", "401040", 48, null, p1);
		builder.createEmptyFunction("addPerson", "4011a0", 48, null, p_list, p_personName);
		builder.createEmptyFunction("__SEH_prolog4", "4019ac", 69, null, p1, p1, p1);
		builder.createEmptyFunction("main", "4012c0", 53, null);
		builder.createStackReference("4012ef", RefType.READ, -8, SourceType.USER_DEFINED, 0);
		Function fun = program.getFunctionManager().getFunctionAt(builder.addr("4012c0"));
		builder.createLocalVariable(fun, null, new Undefined4DataType(), -0x8);

		fun = builder.createEmptyFunction("initializePeople", "401150", 69, null, p1);
		builder.createLocalVariable(fun, null, new Undefined4DataType(), -0x8);

		fun = builder.createEmptyFunction("Canary_Init_00401a58", "401a58", 15, null);
		builder.createLocalVariable(fun, null, new Undefined4DataType(), -0x8);
		builder.createLocalVariable(fun, null, new Undefined4DataType(), -0xc);

		//
		//
		//
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent
		program = builder.getProgram();
		AbstractGenericTest.setInstanceField("recordChanges", program, Boolean.TRUE);

		UniversalID ID = UniversalIdGenerator.nextID();

		if (lastGeneratedUniversalID != null) {
			if (!lastGeneratedUniversalID.equals(ID)) {
				// if this happens, update initializeStaticUniversalIDUsage()
				throw new AssertException("Expected Test UniversalID has changed.  "
					+ "This is probably due to an new static usage of the UniversalIDGenerator.");
			}
		}

		return builder.getProgram();
	}
}
