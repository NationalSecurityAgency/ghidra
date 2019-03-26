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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Analyzer Test for Mips Pre-Analyzer
 * 
 */

public class MipsPreAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {
	private TestEnv env;
	private Program program;
	private ProgramContext context;
	private Register pairBitRegister;
	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		program = buildProgram();
		context = program.getProgramContext();
		pairBitRegister = program.getProgramContext().getRegister("PAIR_INSTRUCTION_FLAG");
	}

	@After
	public void tearDown() throws Exception {

		env.dispose();
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

	private Program buildProgram() throws Exception {
		builder = new ProgramBuilder("Test", ProgramBuilder._MIPS);
		builder.createMemory("ONE", "0x1000", 0x2000);

		builder.setBytes("1000", "8a 71 00 04 9a 71 00 07");// normal pair
		builder.setBytes("1008", "89 49 00 14 99 49 00 17");// normal pair

		builder.setBytes("1100", "89 44 00 14 00 a0 38 21 98 c7 00 17 99 44 00 17");// reordered pair

		builder.setBytes("1200", "8b 15 00 04 08 9f a0 60 9b 15 00 07");// delay slot pair

		builder.setBytes("1300", "88 c5 00 14 89 44 00 14 00 a0 38 21 98 c7 00 17");// moved pair

		builder.setBytes("1400", "88 a3 00 14 00 60 58 21 98 ab 00 17");// moved pair

		builder.setBytes("1500", "10 00 00 03 88 de 00 14");// separated pair
		builder.setBytes("1510", "98 de 00 17");// separated pair  (branch to from previous)

		return builder.getProgram();
	}

	@Test
    public void testSimplePair() {
		assertTrue("normal pair", !isPairSet(program, context, pairBitRegister, 0x1000));
		assertTrue("normal pair", !isPairSet(program, context, pairBitRegister, 0x1004));
		assertTrue("normal pair", !isPairSet(program, context, pairBitRegister, 0x1008));
		assertTrue("normal pair", !isPairSet(program, context, pairBitRegister, 0x100c));

		builder.disassemble("0x1000", 16);
//		showTool(0x1000);

		assertTrue("normal pair", isPairSet(program, context, pairBitRegister, 0x1000));
		assertTrue("normal pair", isPairSet(program, context, pairBitRegister, 0x1004));
		assertTrue("normal pair", isPairSet(program, context, pairBitRegister, 0x1008));
		assertTrue("normal pair", isPairSet(program, context, pairBitRegister, 0x100c));
	}

	@Test
    public void testReorderedPair() {
		assertTrue("reordered pair", !isPairSet(program, context, pairBitRegister, 0x1100));
		assertTrue("reordered pair", !isPairSet(program, context, pairBitRegister, 0x110c));

		builder.disassemble("0x1100", 16);
//		showTool("0x1100");

		assertTrue("reordered pair", isPairSet(program, context, pairBitRegister, 0x1100));
		assertTrue("reordered pair", isPairSet(program, context, pairBitRegister, 0x110c));
	}

	@Test
    public void testDelaySlotPair() {
		assertTrue("delay slot pair", !isPairSet(program, context, pairBitRegister, 0x1200));
		assertTrue("delay slot pair", !isPairSet(program, context, pairBitRegister, 0x1208));

		builder.disassemble("0x1200", 12);
//		showTool("0x1200");

		assertTrue("delay slot pair", isPairSet(program, context, pairBitRegister, 0x1200));
		assertTrue("delay slot pair", isPairSet(program, context, pairBitRegister, 0x1208));
	}

	@Test
    public void testMovedPair() {
		assertTrue("moved pair", !isPairSet(program, context, pairBitRegister, 0x1300));
		assertTrue("moved pair", !isPairSet(program, context, pairBitRegister, 0x130c));

		builder.disassemble("0x1300", 16);
//		showTool("0x1300");

		assertTrue("moved pair", isPairSet(program, context, pairBitRegister, 0x1300));
		assertTrue("moved pair", isPairSet(program, context, pairBitRegister, 0x130c));
	}

	@Test
    public void testMovedPair2() {
		assertTrue("moved pair", !isPairSet(program, context, pairBitRegister, 0x1400));
		assertTrue("moved pair", !isPairSet(program, context, pairBitRegister, 0x1408));

		builder.disassemble("0x1400", 12);
//		showTool("0x1400");

		assertTrue("moved pair", isPairSet(program, context, pairBitRegister, 0x1400));
		assertTrue("moved pair", isPairSet(program, context, pairBitRegister, 0x1408));
		assertTrue("moved pair move", !isPairSet(program, context, pairBitRegister, 0x1404));
	}

	@Test
    public void testSeparatedPair() {
		assertTrue("moved pair", !isPairSet(program, context, pairBitRegister, 0x1500));
		assertTrue("moved pair", !isPairSet(program, context, pairBitRegister, 0x1504));
		assertTrue("moved pair", !isPairSet(program, context, pairBitRegister, 0x1510));

		AddressSet set = new AddressSet();
		set.add(addr("0x1500"), addr("0x1508"));
		set.add(addr("0x1510"), addr("0x1514"));
		builder.disassemble(set);
//		showTool("0x1500");

		assertTrue("moved pair", isPairSet(program, context, pairBitRegister, 0x1500));
		assertTrue("moved pair", isPairSet(program, context, pairBitRegister, 0x1504));
		assertTrue("moved pair", isPairSet(program, context, pairBitRegister, 0x1510));
	}

//	private void showTool(String address) {
//		openProgramInTool(program, address);
//	}

	/**
	 * This test analyzes the V850 languages, and then makes sure there are key
	 * things marked up.
	 */
//	public void testMIPSPreAnalysis() throws Exception {
//		String programName = "analysis_regression/MIPSPairInstructionTestFunction.xml";
//
//		Program program1 = null;
//		File file = findTestDataFile(programName);
//
//		program1 = env.getGhidraProject().importProgram(file);
//
//		// disassemble at the start
//		// create a function
//		Address minAddr = program1.getMinAddress();
//		DisassembleCommand disassembleCommand = new DisassembleCommand(minAddr, null, true);
//		disassembleCommand.applyTo(program1);
//		GhidraProject.analyze(program1);
//
//		Register pairBitRegister =
//			program1.getProgramContext().getRegister("PAIR_INSTRUCTION_FLAG");
//
//		// make sure the pcode on LWR and LWL are set correctly
//		Address addr = program1.getMinAddress().getNewAddress(0x627e8258);
//		Instruction instructionAt = program1.getListing().getInstructionAt(addr);
//		Object[] results = instructionAt.getResultObjects();
//		assertTrue("LWR has no effect", instructionAt.getResultObjects().length == 0);
//		addr = program1.getMinAddress().getNewAddress(0x627e8254);
//		instructionAt = program1.getListing().getInstructionAt(addr);
//		results = instructionAt.getResultObjects();
//		assertTrue("LWL has effect", results.length == 1);
//		assertTrue("out reg set", ((Register) results[0]).getName().equals("t0"));
//
//		// make sure all pair instructions found and tagged
//		ProgramContext context = program1.getProgramContext();
//
//		// normal
//		assertTrue("normal pair", isPairSet(program1, context, pairBitRegister, 0x627e7ef4));
//		assertTrue("normal pair", isPairSet(program1, context, pairBitRegister, 0x627e7ef8));
//		assertTrue("normal pair", isPairSet(program1, context, pairBitRegister, 0x627e8094));
//		assertTrue("normal pair", isPairSet(program1, context, pairBitRegister, 0x627e8098));
//
//		// delay slot pair
//		addr = program1.getMinAddress().getNewAddress(0x627e7f48);
//		assertTrue("delay slot disassemble correctly",
//			program1.getListing().getInstructionAt(addr) != null);
//		assertTrue("delay slotted pair", isPairSet(program1, context, pairBitRegister, 0x627e7f44));
//		assertTrue("delay slotted pair", isPairSet(program1, context, pairBitRegister, 0x627e7f4c));
//
//		// out of order
//		assertTrue("reordered pair", isPairSet(program1, context, pairBitRegister, 0x627e7fc8));
//		assertTrue("reordered pair", isPairSet(program1, context, pairBitRegister, 0x627e7fd4));
//
//		// separated
//		assertTrue("separated pair", isPairSet(program1, context, pairBitRegister, 0x627e7f5c));
//		assertTrue("separated pair", isPairSet(program1, context, pairBitRegister, 0x627e7f64));
//
//		// move'ed into another destination.
//		assertTrue("moved pair", isPairSet(program1, context, pairBitRegister, 0x627e7fc4));
//		assertTrue("moved pair", isPairSet(program1, context, pairBitRegister, 0x627e7fd0));
//		assertTrue("moved pair", isPairSet(program1, context, pairBitRegister, 0x627e80cc));
//		assertTrue("moved pair", isPairSet(program1, context, pairBitRegister, 0x627e80d4));
//		assertFalse("moved pair move", isPairSet(program1, context, pairBitRegister, 0x627e80d0));
//
//		// delay slot separated
//		assertTrue("separated pair", isPairSet(program1, context, pairBitRegister, 0x627e80f8));
//		assertTrue("separated pair", isPairSet(program1, context, pairBitRegister, 0x627e826c));
//	}

	private boolean isPairSet(Program prog, ProgramContext pc, Register pbr, long addrOff) {
		Address address = prog.getMinAddress().getNewAddress(addrOff);

		RegisterValue registerValue = pc.getRegisterValue(pbr, address);
		if (registerValue == null) {
			return false;
		}
		return registerValue.getUnsignedValue().intValue() == 1;
	}

//	private void analyze(Program program) {
//		int id = program.startTransaction(
//			testName.getMethodName() + "-" + program.getName() + "-analysis");
//		try {
//			GhidraProject.analyze(program);
//		}
//		finally {
//			program.endTransaction(id, true);
//		}
//	}
//
//	private void compare(String expected, String actual, Language language,
//			CompilerSpec compilerSpec) throws Exception {
//		Program expectedProgram = null;
//		Program actualProgram = null;
//		try {
//			if (language == null) {
//				language = ProjectTestUtils.getSLEIGH_X86_LANGUAGE();
//			}
//			if (compilerSpec == null) {
//				compilerSpec = language.getDefaultCompilerSpec();
//			}
//
//			expectedProgram = env.getProgram(expected);
//
//			File actualFile = getTestDataFile(actual);
//
//			actualProgram =
//				env.getGhidraProject().importProgram(actualFile, language, compilerSpec);
//
//			GhidraProject.analyze(actualProgram);
//
//			ProgramDiff diff = new ProgramDiff(expectedProgram, actualProgram);
//			AddressSetView diffset = diff.getDifferences(getTaskMonitor());
//
//			displayDetails(expectedProgram, actualProgram, diffset);
//
////			String text = "differences detected : ";
////			if (diffset.getNumAddressRanges() != 0) {
////				text += diffset.toString();
////			}
//			//assertEquals(text, 0, diffset.getNumAddressRanges());
//			assertEquals(0, diffset.getNumAddressRanges());
//		}
//		finally {
//			if (expectedProgram != null) {
//				env.release(expectedProgram);
//			}
//			if (actualProgram != null) {
//				project.close(actualProgram);
//			}
//		}
//	}

	private void displayDetails(Program expectedProgram, Program actualProgram,
			AddressSetView diffset) {
		/*
		System.out.println(diffset);  // this call has an adverse impact on the nightly tests!
		if (diffset.getNumAddresses() != 0) {
		    ProgramDiffDetails details = new ProgramDiffDetails(expectedProgram, actualProgram);
		    AddressIterator iter = diffset.getAddresses(true);
		    while (iter.hasNext()) {
		        Address addr = iter.next();
		        System.out.println(details.getDiffDetails(addr));
		        //StyledDocument doc = new DefaultStyledDocument();
		        //details.getAllDetails(diffset.getMinAddress(), doc);
		        //System.out.println(doc.getText(0, doc.getLength()));
		    }
		}
		*/
	}

	private TaskMonitor getTaskMonitor() {
		return TaskMonitorAdapter.DUMMY_MONITOR;
	}
}
