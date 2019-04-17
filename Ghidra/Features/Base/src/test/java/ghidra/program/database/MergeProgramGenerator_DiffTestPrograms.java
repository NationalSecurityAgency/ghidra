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

import java.awt.Color;
import java.util.Date;

import generic.test.AbstractGenericTest;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.*;
import ghidra.util.exception.AssertException;

class MergeProgramGenerator_DiffTestPrograms implements MergeProgramGenerator {

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

	MergeProgramGenerator_DiffTestPrograms(Object consumer) {
		this.consumer = consumer;
	}

	@Override
	public ProgramDB generateProgram(String programName) throws Exception {

		if ("DiffTestPgm1".equals(programName)) {
			return buildDiffTestPgm1();
		}
		else if ("DiffTestPgm2".equals(programName)) {
			return buildDiffTestPgm2();
		}
		else if ("DiffTestPgm1_X86".equals(programName)) {
			return buildDiffTestPgm1_X86();
		}
		else if ("DiffTestPgm1_X86_64".equals(programName)) {
			return buildDiffTestPgm1_X86_64();
		}
		throw new AssertException("Add new builder for program: " + programName);
	}

	private ProgramDB buildDiffTestPgm1() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("DiffTestPgm1", true, consumer);

		builder.createMemory("d1", "0x100", 0x100);
		builder.createMemory("d2", "0x200", 0x100);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".datau", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		// code units
		builder.addBytesFallthrough("100203f");
		builder.disassemble("0x100203f", 1);
		builder.addBytesMoveImmediate("0x100230d", (byte) 1);
		builder.disassemble("0x100230d", 1);

		builder.addBytesNOP("0x100354f", 2);
		builder.disassemble("0x100354f", 1);

		// data
		// CodeUnitMergerManagerTest - checks disassembly and data
		//@formatter:off
		builder.setBytes("0x10013d6", new byte[] { 
			0x6d, 0x00, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x50, 0x65, 0x6e, 0x41  
		});
		//@formatter:on

		// comments
		builder.createComment("1002304", "EOL comment", CodeUnit.EOL_COMMENT);
		builder.createComment("1002306", "\"Pre Comment\"", CodeUnit.PRE_COMMENT);
		builder.createComment("100230c", "Post comment", CodeUnit.POST_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.PRE_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.EOL_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.POST_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.REPEATABLE_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.PLATE_COMMENT);

		builder.createComment("1002312", "\"My comment that the other comment is in.\"",
			CodeUnit.PRE_COMMENT);
		builder.createComment("1002312", "My comment that the other comment is in.",
			CodeUnit.EOL_COMMENT);
		builder.createComment("1002312", "My comment that the other comment is in.",
			CodeUnit.POST_COMMENT);

		builder.createComment("1002040", "Pre in P1.", CodeUnit.PRE_COMMENT);
		builder.createComment("1002040", "EOL in P1.", CodeUnit.EOL_COMMENT);
		builder.createComment("1002040", "Post in P1.", CodeUnit.POST_COMMENT);
		builder.createComment("1002040", "Plate in P1.", CodeUnit.PLATE_COMMENT);
		builder.createComment("1002040", "Repeatable in P1.", CodeUnit.REPEATABLE_COMMENT);

		// data types
		builder.addCategory(new CategoryPath("/cat1"));

		// for FunctionMergeManager2Test
		//
		DataType dt = new ByteDataType();
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction(null, "10018cf", 10, null, p);
		builder.createEmptyFunction(null, "100299e", 10, null, p, p, p);
		builder.createEmptyFunction(null, "1002cf5", 10, null, p, p, p, p, p);

		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		ProgramDB program = builder.getProgram();

		builder.setIntProperty("10018ae", "Space", 1);
		builder.setIntProperty("10018ba", "Space", 1);
		builder.setIntProperty("10018ff", "Space", 1);
		builder.setIntProperty("100248c", "Space", 1);

		builder.setObjectProperty("100248c", "testColor", new SaveableColor(Color.CYAN));
		builder.setObjectProperty("10039dd", "testColor", new SaveableColor(Color.BLACK));
		builder.setObjectProperty("10039f8", "testColor", new SaveableColor(Color.BLACK));
		builder.setObjectProperty("10039fe", "testColor", new SaveableColor(Color.RED));

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

	private ProgramDB buildDiffTestPgm2() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("DiffTestPgm1", true, consumer);

		builder.createMemory("d1", "0x100", 0x100);
		builder.createMemory("d2", "0x200", 0x100);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".datau", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		ProgramDB program = builder.getProgram();

		builder.setIntProperty("10018ba", "Space", 1);
		builder.setIntProperty("10018ce", "Space", 2);
		builder.setIntProperty("10018ff", "Space", 2);
		builder.setIntProperty("1002428", "Space", 1);
		builder.setIntProperty("100248c", "Space", 1);

		builder.setObjectProperty("100248c", "testColor", new SaveableColor(Color.WHITE));
		builder.setObjectProperty("10039f1", "testColor", new SaveableColor(Color.BLACK));
		builder.setObjectProperty("10039f8", "testColor", new SaveableColor(Color.BLACK));
		builder.setObjectProperty("10039fe", "testColor", new SaveableColor(Color.GREEN));

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

	private ProgramDB buildDiffTestPgm1_X86() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DiffTestPgm1", ProgramBuilder._X86, consumer);

		builder.createMemory("d1", "0x100", 0x100);
		builder.createMemory("d2", "0x200", 0x100);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".datau", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		// for FunctionMergeManager2Test
		//
		DataType dt = new ByteDataType();
		ProgramDB program = builder.getProgram();
		Register al = program.getRegister("AL");
		Register ah = program.getRegister("AH");
		Register dr0 = program.getRegister("DR0");
		Register dr1 = program.getRegister("DR1");
		Register dh = program.getRegister("DH");
		Register cs = program.getRegister("CS");
		Register ecx = program.getRegister("ECX");
		Parameter p1 = new ParameterImpl(null, dt, 8, builder.getProgram());
		Parameter p2 = new ParameterImpl(null, dt, 12, builder.getProgram());
		Parameter p3 = new ParameterImpl(null, dt, 16, builder.getProgram());
		Parameter p4 = new ParameterImpl(null, dt, 20, builder.getProgram());
		Parameter p5 = new ParameterImpl(null, dt, 24, builder.getProgram());
		Parameter p_al = new ParameterImpl(null, dt, al, builder.getProgram());
		Parameter p_fee = new ParameterImpl("fee", dt, al, builder.getProgram());
		Parameter p_ah = new ParameterImpl(null, dt, ah, builder.getProgram());
		Parameter p_cs = new ParameterImpl(null, dt, cs, builder.getProgram());
		Parameter p_dr0 = new ParameterImpl(null, dt, dr0, builder.getProgram());
		Parameter p_dr1 = new ParameterImpl(null, dt, dr1, builder.getProgram());
		Parameter p_dh = new ParameterImpl(null, dt, dh, builder.getProgram());
		Parameter p_ecx = new ParameterImpl(null, dt, ecx, builder.getProgram());
		builder.createEmptyFunction(null, null, null, true, "10018cf", 10, null, p_al);
		builder.createEmptyFunction(null, null, null, true, "100299e", 10, null, p_fee, p_ah, p_dr1);
		builder.createEmptyFunction(null, null, null, true, "1002cf5", 10, null, p1, p_cs, p3, p4,
			p5);
		builder.createEmptyFunction(null, null, null, true, "1002c93", 10, null, p_ecx, p1, p2);
		builder.createEmptyFunction(null, null, null, true, "10030e4", 10, null, p_dh);
		builder.createEmptyFunction(null, null, null, true, "1004bc0", 10, null, p_dr0);

		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		builder.setRegisterValue("DR0", "10022d4", "10022e5", 0x1010101);
		builder.setRegisterValue("DR0", "100230b", "100231c", 0xa4561427);
		builder.setRegisterValue("DR0", "1002329", "100233b", 0x40e20100);
		builder.setRegisterValue("DR0", "1003bfc", "1003c10", 0x91ef0600);
		builder.setRegisterValue("DR0", "1003c1c", "1003c36", 0x71f25b2e);

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

	private ProgramDB buildDiffTestPgm1_X86_64() throws Exception {
		ProgramBuilder builder =
			new ProgramBuilder("DiffTestPgm1", ProgramBuilder._X64, "windows", consumer);

		builder.createMemory("block1", "1000", 1000);
		ProgramDB program = builder.getProgram();

		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		AbstractGenericTest.setInstanceField("recordChanges", program, Boolean.TRUE);

		builder.createEmptyFunction("bob", "1000", 20, new VoidDataType());

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
