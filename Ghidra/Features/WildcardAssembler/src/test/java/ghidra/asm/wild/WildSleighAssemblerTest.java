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
package ghidra.asm.wild;

import static org.hamcrest.Matchers.hasItem;
import static org.junit.Assert.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import ghidra.asm.wild.symbol.WildAssemblyTerminal;
import ghidra.asm.wild.tree.WildAssemblyParseToken.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.util.NumericUtilities;

public class WildSleighAssemblerTest extends AbstractGhidraHeadlessIntegrationTest {

	static SleighLanguage toy;
	static WildSleighAssembler asmToy;
	static SleighLanguage arm;
	static WildSleighAssembler asmArm;
	static SleighLanguage mips;
	static WildSleighAssembler asmMips;
	static SleighLanguage x86;
	static WildSleighAssembler asmX86;
	static Program x86Program;
	static SleighLanguage x8664;
	static WildSleighAssembler asmX8664;
	static Program x8664Program;

	protected static void toy() throws Exception {
		if (toy != null) {
			return;
		}
		toy =
			(SleighLanguage) getLanguageService().getLanguage(new LanguageID("Toy:BE:64:default"));
		WildSleighAssemblerBuilder builder = new WildSleighAssemblerBuilder(toy);
		asmToy = builder.getAssembler(new AssemblySelector());
	}

	protected static void arm() throws Exception {
		if (arm != null) {
			return;
		}
		ProgramBuilder armProgramBuilder = new ProgramBuilder("arm_le_test", "ARM:LE:32:v8");
		armProgramBuilder.setBytes(String.format("0x%08X", 0x0),
			"00 00 a0 e1 00 00 a0 e1 00 00 a0 e1 fb ff ff eb 00 00 a0 e1");
		Program armProgram = armProgramBuilder.getProgram();
		arm = (SleighLanguage) armProgram.getLanguage();
		WildSleighAssemblerBuilder builderArm = new WildSleighAssemblerBuilder(arm);
		asmArm = builderArm.getAssembler(new AssemblySelector(), armProgram);
	}

	protected static void mips() throws Exception {
		if (mips != null) {
			return;
		}
		ProgramBuilder mipsProgramBuilder = new ProgramBuilder("mips_test", "MIPS:BE:32:default");
		// The following is:
		// 0x00000000: jalx 0x8
		// 0x00000004: nop
		// 0x00000008: restore 0x1b8,ra,s0-s1
		// 0x0000000c: nop
		mipsProgramBuilder.setBytes("0x00000000",
			"0c 00 00 08 00 00 00 00 f0 30 64 77 00 00 00 00");
		// This line sets the binary at addresses 0x8-0xc to be MIPS 16 (e.g. the
		// restore instruction above)
		mipsProgramBuilder.setRegisterValue("ISA_MODE", "0x8", "0xc", 1);
		mipsProgramBuilder.disassemble("0x00000000", 0x10);
		var mipsProgram = mipsProgramBuilder.getProgram();
		mips = (SleighLanguage) mipsProgram.getLanguage();
		WildSleighAssemblerBuilder mipsBuilder = new WildSleighAssemblerBuilder(mips);
		asmMips = mipsBuilder.getAssembler(new AssemblySelector(), mipsProgram);
	}

	protected static void x86() throws Exception {
		if (x86 != null) {
			return;
		}
		ProgramBuilder x86ProgramBuilder = new ClassicSampleX86ProgramBuilder();
		x86Program = x86ProgramBuilder.getProgram();
		x86 = (SleighLanguage) x86Program.getLanguage();
		WildSleighAssemblerBuilder builderX86 = new WildSleighAssemblerBuilder(x86);
		asmX86 = builderX86.getAssembler(new AssemblySelector(), x86Program);
	}

	protected static void x8664() throws Exception {
		if (x8664 != null) {
			return;
		}
		ProgramBuilder x8664ProgramBuilder = new ProgramBuilder("x86_64_test", "x86:LE:64:default");
		x8664Program = x8664ProgramBuilder.getProgram();
		x8664 = (SleighLanguage) x8664Program.getLanguage();
		WildSleighAssemblerBuilder builderX8664 = new WildSleighAssemblerBuilder(x8664);
		asmX8664 = builderX8664.getAssembler(new AssemblySelector(), x8664Program);
	}

	protected void dumpResults(AssemblyResolutionResults results) {
		System.err.println("results:" + results);
		for (AssemblyResolution res : results) {
			if (res instanceof WildAssemblyResolvedPatterns pats) {
				System.err.println(pats.getInstruction());
				for (WildOperandInfo info : pats.getOperandInfo()) {
					var choice_str = "?";
					var choice = info.choice();
					if (choice != null) {
						choice_str = choice.toString();
					}

					System.err.println(info.location() + ": " + info.wildcard() + " = " +
						info.expression() + "(" + info.path() + ") == " + choice_str.toString());
				}
			}
		}
	}

	/**
	 * Return all items from {@code results} which are instances of
	 * {@code WildAssemblyResolvedPatterns}
	 * 
	 * @param results
	 * @return
	 */
	protected List<WildAssemblyResolvedPatterns> getValidResults(
			AssemblyResolutionResults results) {
		var out = new ArrayList<WildAssemblyResolvedPatterns>();
		for (AssemblyResolution res : results) {
			if (res instanceof WildAssemblyResolvedPatterns pats) {
				out.add(pats);
			}
		}
		return out;
	}

	/**
	 * Return all Choice values for the given {@code wildcardIdentifier} found in the given
	 * {@code results}
	 * 
	 * @param wildcardIdentifier
	 * @param results
	 * @return
	 */
	protected List<String> getChoiceValues(String wildcardIdentifier,
			AssemblyResolutionResults results) {
		return getValidResults(results).stream()
				.flatMap(x -> x.getOperandInfo()
						.stream()
						.filter(oi -> oi.wildcard().equals(wildcardIdentifier))
						.filter(oi -> oi.choice() != null)
						.map(oi -> oi.choice().toString()))
				.toList();
	}

	protected Set<AssemblyPatternBlock> getInstructionPatterns(AssemblyResolutionResults results) {
		return getValidResults(results).stream()
				.map(res -> res.getInstruction())
				.collect(Collectors.toSet());
	}

	protected Set<AssemblyPatternBlock> makeInstructionPatterns(String... patterns) {
		return Stream.of(patterns)
				.map(AssemblyPatternBlock::fromString)
				.collect(Collectors.toSet());
	}

	/**
	 * Return all possible instruction encodings from the given {@code results}
	 * 
	 * @param results the assembly results whose instruction bytes to collect
	 * @return the full list of results
	 */
	protected List<byte[]> getInstructionValues(AssemblyResolutionResults results) {
		var out = new ArrayList<byte[]>();
		for (WildAssemblyResolvedPatterns res : getValidResults(results)) {
			for (byte[] instructionVal : res.getInstruction().possibleVals()) {
				// Read the docs on possibleVals(). You must create a copy.
				out.add(Arrays.copyOf(instructionVal, instructionVal.length));
			}
		}
		return out;
	}

	/**
	 * Return all possible instruction encodings as hex strings from the given {@code results}
	 * 
	 * @param results the results to encode and collect
	 * @return the list
	 */
	protected List<String> getInstructionValuesHex(AssemblyResolutionResults results) {
		return getInstructionValues(results).stream()
				.map(x -> NumericUtilities.convertBytesToString(x, ":"))
				.toList();
	}

	@Test
	public void testWildRegex() {
		Pattern patWild = WildAssemblyTerminal.PAT_WILD;

		Matcher mat = patWild.matcher("`test` more` and `more`");

		assertTrue(mat.find(0));
		assertEquals("`test`", mat.group());
	}

	@Test
	public void testSpecRegexWildcard() {
		assertEquals(new RegexWildcard("Q1", Pattern.compile("r.")), Wildcard.parse("Q1/r."));
	}

	@Test
	public void testSpecNumericWildcard() {
		assertEquals(new NumericWildcard("Q1"), Wildcard.parse("Q1[..]"));
	}

	@Test
	public void testSpecRangesWildcard() {
		assertEquals(new RangesWildcard("Q1", List.of(new WildRange(1, 1))),
			Wildcard.parse("Q1[1]"));
		assertEquals(new RangesWildcard("Q1", List.of(new WildRange(1, 2))),
			Wildcard.parse("Q1[1..2]"));
		assertEquals(new RangesWildcard("Q1", List.of(
			new WildRange(-16, -4),
			new WildRange(1, 2))),
			Wildcard.parse("Q1[1..2,-0x10..-4]"));
	}

	@Test
	public void testRangesTest() {
		Wildcard wild = Wildcard.parse("Q1[1..2,-0x10..-4]");

		assertFalse(wild.test("r1"));

		assertTrue(wild.test(1));
		assertTrue(wild.test(2));
		assertFalse(wild.test(0));
		assertFalse(wild.test(3));

		assertTrue(wild.test(-16));
		assertTrue(wild.test(-10));
		assertTrue(wild.test(-4));
		assertFalse(wild.test(-17));
		assertFalse(wild.test(-3));

		assertTrue(wild.test(-10L));
	}

	@Test
	public void testParseWildRegOp_Toy() throws Exception {
		toy();
		Collection<AssemblyParseResult> parses = asmToy.parseLine("add `Q1`, #6");
		assertTrue(parses.stream().anyMatch(p -> !p.isError()));
	}

	@Test
	public void testParseWildImm_Toy() throws Exception {
		toy();
		Collection<AssemblyParseResult> parses = asmToy.parseLine("add r0, #`Q2`");
		assertTrue(parses.stream().anyMatch(p -> !p.isError()));
	}

	@Test
	public void testParseWildStr_Err_Toy() throws Exception {
		toy();
		Collection<AssemblyParseResult> parses = asmToy.parseLine("add r0, `Q3`6");
		assertFalse(parses.stream().anyMatch(p -> !p.isError()));
	}

	@Test
	public void testParseWildRegAndImmOp_Toy() throws Exception {
		toy();
		Collection<AssemblyParseResult> parses = asmToy.parseLine("add `Q1`, #`Q2`");
		assertTrue(parses.stream().anyMatch(p -> !p.isError()));
	}

	@Test
	public void testParseAndResolveWildRegOp_Toy() throws Exception {
		toy();
		Collection<AssemblyParseResult> parses = asmToy.parseLine("add `Q1/r.`, #6");
		AssemblyParseResult one = Unique.assertOne(parses.stream().filter(p -> !p.isError()));
		System.err.println("parse: " + one);

		Address addr0 = toy.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		AssemblyResolutionResults results = asmToy.resolveTree(one, addr0);
		dumpResults(results);

		assertEquals(
			makeInstructionPatterns("C8:06", "C8:16", "C8:26", "C8:36", "C8:46", "C8:56", "C8:66",
				"C8:76", "C8:86", "C8:96"),
			getInstructionPatterns(results));
	}

	@Test
	public void testParseAndResolveWildImmOp_Toy() throws Exception {
		toy();
		Collection<AssemblyParseResult> parses = asmToy.parseLine("add r0, #`Q2[0,2..4]`");
		AssemblyParseResult one = Unique.assertOne(parses.stream().filter(p -> !p.isError()));
		System.err.println("parse: " + one);

		Address addr0 = toy.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		AssemblyResolutionResults results = asmToy.resolveTree(one, addr0);
		dumpResults(results);

		assertEquals(makeInstructionPatterns("C8:00", "C8:02", "C8:03", "C8:04"),
			getInstructionPatterns(results));
	}

	@Test
	public void testParseAndResolveWildSubTree_Toy() throws Exception {
		toy();
		Collection<AssemblyParseResult> parses =
			asmToy.parseLine("add r0, `!Q2`").stream().filter(p -> !p.isError()).toList();

		Address addr0 = toy.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		var allValidPatterns = new HashSet<AssemblyPatternBlock>();
		for (AssemblyParseResult p : parses) {
			System.err.println("parse: " + p);
			AssemblyResolutionResults results = asmToy.resolveTree(p, addr0);
			dumpResults(results);
			allValidPatterns.addAll(getInstructionPatterns(results));
		}
		assertEquals(makeInstructionPatterns(
			"C8:0X", // Unspecified immediate op
			// enumerated register ops
			"C0:00", "C0:01", "C0:02", "C0:03", "C0:04", "C0:05", "C0:06", "C0:07",
			"C0:08", "C0:09", "C0:0A", "C0:0B", "C0:0C", "C0:0D", "C0:0E", "C0:0F"),
			allValidPatterns);
	}

	@Test
	public void testParseAndResolveWildNotSubTree_Toy() throws Exception {
		toy();
		Collection<AssemblyParseResult> parses =
			asmToy.parseLine("add r0, `Q2`").stream().filter(p -> !p.isError()).toList();

		Address addr0 = toy.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		var allValidPatterns = new HashSet<AssemblyPatternBlock>();
		for (AssemblyParseResult p : parses) {
			System.err.println("parse: " + p);
			AssemblyResolutionResults results = asmToy.resolveTree(p, addr0);
			dumpResults(results);
			allValidPatterns.addAll(getInstructionPatterns(results));
		}
		assertEquals(makeInstructionPatterns(
			// Immediate op is excluded, because Toy's Sleigh spec wants a # on the literal
			// enumerated register ops
			"C0:00", "C0:01", "C0:02", "C0:03", "C0:04", "C0:05", "C0:06", "C0:07",
			"C0:08", "C0:09", "C0:0A", "C0:0B", "C0:0C", "C0:0D", "C0:0E", "C0:0F"),
			allValidPatterns);
	}

	@Test
	public void testMov_arm() throws Exception {
		arm();
		Collection<AssemblyParseResult> parses = asmArm.parseLine("mov `Q1`, #0x0");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidChoices = new ArrayList<String>();
		var allValidEncodings = new ArrayList<String>();
		Address addr0 = arm.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmArm.resolveTree(r, addr0);
			dumpResults(results);
			allValidChoices.addAll(getChoiceValues("Q1", results));
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		// This is the encoding of "mov pc,#0x0"
		assertThat("Expected to have a Q1=='pc' encoding",
			allValidEncodings, hasItem("00:f0:a0:e3"));
		// This is the encoding of "mov r5,#0x0"
		assertThat("Expected to have a Q1=='r5' encoding",
			allValidEncodings, hasItem("00:50:a0:e3"));

		assertEquals(Set.of(
			"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
			"r8", "r9", "r10", "r11", "r12", "lr", "sp", "pc"),
			Set.copyOf(allValidChoices));
	}

	@Test
	public void testSub_arm() throws Exception {
		arm();
		Collection<AssemblyParseResult> parses = asmArm.parseLine("sub r1,r1,#0x200");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidEncodings = new ArrayList<String>();
		Address addr0 = arm.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmArm.resolveTree(r, addr0);
			dumpResults(results);
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		assertTrue("Expect to have one valid encoding", allValidEncodings.size() == 1);
		assertTrue("Expect to have 02:1c:41:e2 as an encoding",
			allValidEncodings.contains("02:1c:41:e2"));
	}

	@Test
	public void testSubWildcard_arm() throws Exception {
		arm();
		Collection<AssemblyParseResult> parses = asmArm.parseLine("sub `Q3/r.`,`Q4`,#0x200");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidEncodings = new ArrayList<String>();
		Address addr0 = arm.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmArm.resolveTree(r, addr0);
			dumpResults(results);
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		assertTrue("Expect to have multiple valid encodings", allValidEncodings.size() > 0);
	}

	@Test
	public void testRestore_mips() throws Exception {
		mips();
		Collection<AssemblyParseResult> parses = asmMips.parseLine("restore 0x1b8,ra,s0-s1");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidEncodings = new ArrayList<String>();
		Address addr8 = mips.getAddressFactory().getDefaultAddressSpace().getAddress(8);

		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmMips.resolveTree(r, addr8);
			dumpResults(results);
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		assertThat(allValidEncodings, hasItem("f0:30:64:77"));
	}

	@Test
	public void testRestoreWild_mips() throws Exception {
		mips();
		Collection<AssemblyParseResult> parses = asmMips.parseLine("restore `Q1`,ra,s0-s1");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidResults = new ArrayList<WildAssemblyResolvedPatterns>();
		Address addr8 = mips.getAddressFactory().getDefaultAddressSpace().getAddress(8);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmMips.resolveTree(r, addr8);
			dumpResults(results);
			allValidResults.addAll(getValidResults(results));
		}

		// I expect at least an encoding like 0xf0306477 (see "testRestore_mips" test)
		assertFalse(allValidResults.isEmpty());
	}

	@Test
	public void testLw_mips() throws Exception {
		mips();
		Collection<AssemblyParseResult> parses = asmMips.parseLine("lw `Q1`,0x0(a0)");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidEncodings = new ArrayList<String>();
		// Note here, be sure to go past the mips16 code at the start of our fake
		// program
		Address addr0 = mips.getAddressFactory().getDefaultAddressSpace().getAddress(0x100);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmMips.resolveTree(r, addr0);
			dumpResults(results);
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		// Build all 32 encodings (one per target register, Q1) and verify they're in
		// the results
		byte[] expected = NumericUtilities.convertStringToBytes("8c800000");
		for (var i = 1; i < 32; i++) {
			expected[1] = (byte) (0x80 + i);
			String expectedHex = NumericUtilities.convertBytesToString(expected, ":");
			assertTrue("Expected to have " + expectedHex + " as an encoding",
				allValidEncodings.contains(expectedHex));
		}

		assertEquals(32, allValidEncodings.size());
	}

	@Test
	public void testCall_x86() throws Exception {
		x86();
		Collection<AssemblyParseResult> parses = asmX86.parseLine("CALL 0x004058f3");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidEncodings = new ArrayList<String>();
		Address addr0 = x86.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX86.resolveTree(r, addr0);
			dumpResults(results);
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		// These are the two encodings Ghidra suggests when using the "Patch
		// Instruction" right-click menu option
		assertEquals(Set.of(
			"e8:ee:58:40:00",
			"67:e8:ed:58:40:00"),
			Set.copyOf(allValidEncodings));
	}

	@Test
	public void testCallWildcard_x86() throws Exception {
		x86();
		Collection<AssemblyParseResult> parses =
			asmX86.parseLine("CALL `Q1[0x00400000..0x00400003]`");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidResults = new ArrayList<WildAssemblyResolvedPatterns>();
		var allValidEncodings = new ArrayList<String>();
		Address addr0 = x86.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX86.resolveTree(r, addr0);
			dumpResults(results);
			allValidResults.addAll(getValidResults(results));
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		assertEquals(Set.of(
			"e8:fb:ff:3f:00", "e8:fc:ff:3f:00", "e8:fd:ff:3f:00", "e8:fe:ff:3f:00",
			"67:e8:fa:ff:3f:00", "67:e8:fb:ff:3f:00", "67:e8:fc:ff:3f:00", "67:e8:fd:ff:3f:00"),
			Set.copyOf(allValidEncodings));

		WildAssemblyResolvedPatterns call0x00400000 = Unique.assertOne(allValidResults.stream()
				.filter(r -> r.getInstruction()
						.equals(AssemblyPatternBlock.fromString("e8:fb:ff:3f:00"))));
		WildOperandInfo targetInfo = Unique.assertOne(call0x00400000.getOperandInfo());
		assertEquals("Q1", targetInfo.wildcard());
		assertEquals(AssemblyPatternBlock.fromString("SS:FF:FF:FF:FF"), targetInfo.location());
		assertEquals(0x00400000L, targetInfo.choice());
	}

	@Test
	public void testMov_x86() throws Exception {
		x86();
		Collection<AssemblyParseResult> parses = asmX86.parseLine("MOV EBP,`Q1/E.P`");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidEncodings = new ArrayList<String>();
		Address addr0 = x86Program.getMinAddress();
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX86.resolveTree(r, addr0);
			dumpResults(results);
			// This will blow up if the numeric values for Q1 are still in the results
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		// These are the four encodings Ghidra suggests when using the "Patch
		// Instruction" right-click menu option
		assertEquals(Set.of(
			// These two are when Q1 == "EBP"
			"89:ed", "8b:ed",
			// These two are when Q1 == "ESP"
			"89:e5", "8b:ec"),
			Set.copyOf(allValidEncodings));
	}

	@Test
	public void testShrd_x86() throws Exception {
		x86();
		Collection<AssemblyParseResult> parses = asmX86.parseLine("SHRD EAX,EBX,0x7");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidEncodings = new ArrayList<String>();
		Address addr0 = x86Program.getMinAddress();
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX86.resolveTree(r, addr0);
			dumpResults(results);
			// This will blow up if the numeric values for Q1 are still in the results
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		assertEquals(1, allValidEncodings.size());

		var expectedEncodings = List.of("0f:ac:d8:07");
		for (String expected : expectedEncodings) {
			assertTrue("Expected to have " + expected + " as an encoding",
				allValidEncodings.contains(expected));
		}
	}

	@Test
	public void testShrdWildcard_x86() throws Exception {
		x86();
		Collection<AssemblyParseResult> parses = asmX86.parseLine("SHRD EAX,EBX,`Q1[..]`");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidResults = new ArrayList<WildAssemblyResolvedPatterns>();
		Address addr0 = x86Program.getMinAddress();
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX86.resolveTree(r, addr0);
			dumpResults(results);
			allValidResults.addAll(getValidResults(results));
		}

		WildAssemblyResolvedPatterns res = Unique.assertOne(allValidResults);

		assertEquals(AssemblyPatternBlock.fromString("0F:AC:D8"), res.getInstruction());
		assertEquals(1, res.getOperandInfo().size());
		WildOperandInfo wild = res.getOperandInfo().iterator().next();
		assertEquals("Q1", wild.wildcard());
		assertEquals(
			"The Q1 operand should be the final byte of this instruction... (e.g. after the 0xD8)",
			AssemblyPatternBlock.fromString("SS:SS:SS:FF"), wild.location());
	}

	@Test
	public void testCallDx_x86() throws Exception {
		x86();
		Collection<AssemblyParseResult> parses = asmX86.parseLine("CALL DX");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidEncodings = new ArrayList<String>();
		Address addr0 = x86.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX86.resolveTree(r, addr0);
			dumpResults(results);
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		// These are the three encodings Ghidra suggests when using the "Patch
		// Instruction" right-click menu option
		assertEquals(Set.of("67:66:ff:d2", "66:67:ff:d2", "66:ff:d2"),
			Set.copyOf(allValidEncodings));
	}

	@Test
	public void testCallDx_x8664() throws Exception {
		x8664();
		Collection<AssemblyParseResult> parses = asmX8664.parseLine("CALL DX");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidEncodings = new ArrayList<String>();
		Address addr0 = x8664.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX8664.resolveTree(r, addr0);
			dumpResults(results);
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		// This is the encoding Ghidra suggests when using the "Patch
		// Instruction" right-click menu option
		assertEquals(List.of("66:ff:d2"), allValidEncodings);
	}

	@Test
	public void testCallDxWild_x8664() throws Exception {
		x8664();
		Collection<AssemblyParseResult> parses = asmX8664.parseLine("CALL `Q1/(C|D)X`");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidChoices = new ArrayList<String>();
		var allValidResults = new ArrayList<AssemblyPatternBlock>();
		Address addr0 = x8664.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX8664.resolveTree(r, addr0);
			dumpResults(results);
			allValidChoices.addAll(getChoiceValues("Q1", results));
			allValidResults.addAll(
				getValidResults(results).stream().map(x -> x.getInstruction()).toList());
		}

		assertEquals(Set.of("CX", "DX"), Set.copyOf(allValidChoices));
		assertEquals(
			makeInstructionPatterns("66:ff:d2", "66:ff:d1"),
			Set.copyOf(allValidResults));
	}

	@Test
	public void testLea_x8664() throws Exception {
		x8664();
		Collection<AssemblyParseResult> parses = asmX8664.parseLine("LEA EAX, [ EDX + -0x6c ]");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidResults = new ArrayList<AssemblyPatternBlock>();
		var allValidEncodings = new ArrayList<String>();
		Address addr0 = x8664.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX8664.resolveTree(r, addr0);
			dumpResults(results);
			allValidResults.addAll(
				getValidResults(results).stream().map(x -> x.getInstruction()).toList());
			allValidEncodings.addAll(getInstructionValuesHex(results));
		}

		assertTrue(allValidResults.size() > 0);
		assertEquals(Set.of(
			"67:8d:42:94",
			"67:8d:44:22:94",
			"67:8d:44:62:94",
			"67:8d:44:a2:94",
			"67:8d:44:e2:94",
			"67:8d:82:94:ff:ff:ff",
			"67:8d:84:22:94:ff:ff:ff",
			"67:8d:84:62:94:ff:ff:ff",
			"67:8d:84:a2:94:ff:ff:ff",
			"67:8d:84:e2:94:ff:ff:ff"),
			Set.copyOf(allValidEncodings));
	}

	@Test
	public void testLeaWild_x8664() throws Exception {
		x8664();
		Collection<AssemblyParseResult> parses =
			asmX8664.parseLine("LEA EAX, [ `Q1/EDX` + -0x6c ]");
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		var allValidChoices = new ArrayList<String>();
		var allValidResults = new ArrayList<WildAssemblyResolvedPatterns>();
		Address addr0 = x8664.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX8664.resolveTree(r, addr0);
			dumpResults(results);
			allValidChoices.addAll(getChoiceValues("Q1", results));
			allValidResults.addAll(getValidResults(results));
		}

		WildAssemblyResolvedPatterns shortest =
			Unique.assertOne(allValidResults.stream().filter(r -> r.getInstructionLength() == 4));
		assertEquals(AssemblyPatternBlock.fromString("67:8d:42:94"), shortest.getInstruction());
		WildOperandInfo opInfoEDX = Unique.assertOne(
			shortest.getOperandInfo().stream().filter(x -> x.choice().toString().equals("EDX")));
		assertEquals(AssemblyPatternBlock.fromString("SS:SS:X[x111]"), opInfoEDX.location());
		assertEquals(Set.of("EDX"), Set.copyOf(allValidChoices));
	}
}
