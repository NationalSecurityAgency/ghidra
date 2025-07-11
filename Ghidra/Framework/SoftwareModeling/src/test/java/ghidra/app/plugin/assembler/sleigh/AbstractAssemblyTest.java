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
package ghidra.app.plugin.assembler.sleigh;

import static org.junit.Assert.fail;

import java.util.*;

import org.apache.commons.collections4.MultiValuedMap;
import org.junit.After;
import org.junit.Before;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.generic.util.datastruct.TreeSetValuedTreeMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;

/**
 * A test for assembly of a particular SLEIGH language
 */
public abstract class AbstractAssemblyTest extends AbstractGenericTest {
	public static final long DEFAULT_ADDR = 0x40000000L;

	static SleighLanguage lang;
	static AssemblyDefaultContext context;

	// note: disable debug output in batch mode--over 15M of output to the test log

	static String setupLangID = "";

	/**
	 * Get the ID of the language under test The test case will automatically attempt to obtain a
	 * suitable assembler before the first test is run.
	 *
	 * @return the ID of the language
	 */
	protected abstract LanguageID getLanguageID();

	//protected TabbingOutputStream oldOutput;

	//@Rule
	//public TestName name = new TestName();

	@Before
	public void setUp() throws Exception {
		LanguageID langID = getLanguageID();
		if (!setupLangID.equals(langID.toString())) {
			lang = getLanguage(langID);
			context = new AssemblyDefaultContext(lang);
			setupLangID = langID.toString();
		}
		//oldOutput = dbg.setOutputStream(new FileOutputStream(name.getMethodName() + ".asm.log"));
	}

	@After
	public void tearDown() {
		//dbg.resetOutputStream(oldOutput).close();
	}

	private static SleighLanguage getLanguage(LanguageID langID) throws LanguageNotFoundException {
		LanguageService languageService = DefaultLanguageService.getLanguageService();
		return (SleighLanguage) languageService.getLanguage(langID);
	}

	/**
	 * Disassemble an instruction, presumably the result of assembly
	 *
	 * @param addr the address of the instruction
	 * @param ins the instruction bytes
	 * @param ctx the input context
	 * @return the resulting decoded instruction
	 * @throws InsufficientBytesException
	 * @throws UnknownInstructionException
	 * @throws AddressOverflowException
	 * @throws MemoryAccessException
	 */
	protected PseudoInstruction disassemble(long addr, byte[] ins, byte[] ctx)
			throws InsufficientBytesException, UnknownInstructionException,
			AddressOverflowException, MemoryAccessException {
		Address at = lang.getDefaultSpace().getAddress(addr);
		context.setContextRegister(ctx);
		MemBuffer buf = new ByteMemBufferImpl(at, ins, lang.isBigEndian());
		InstructionPrototype ip = lang.parse(buf, context, false);
		return new PseudoInstruction(at, ip, buf, context);
	}

	/**
	 * Get the constructor tree of the given instruction
	 *
	 * @see SleighInstructionPrototype#dumpConstructorTree()
	 * @param ins the instruction unit
	 * @return the constructor tree
	 */
	protected String dumpConstructorTree(PseudoInstruction ins) {
		SleighInstructionPrototype ip = (SleighInstructionPrototype) ins.getPrototype();
		return ip.dumpConstructorTree();
	}

	/**
	 * Conveniently format the instruction mnemonic and constructor tree
	 *
	 * @param ins the instruction unit
	 * @return a nice display
	 */
	protected String formatWithCons(PseudoInstruction ins) {
		return ins.toString() + " " + dumpConstructorTree(ins);
	}

	/**
	 * Confirm that one of the assembly results matches the pattern described by instr
	 *
	 * @param instr a hex-ish representation of the instruction pattern
	 * @see AssemblyPatternBlock#fromString(String)
	 * @param rr the collection of assembly resolutions
	 */
	protected void checkOneCompat(String instr, AssemblyResolutionResults rr) {
		AssemblyPatternBlock ins = AssemblyPatternBlock.fromString(instr);
		Set<AssemblyResolvedError> errs = new TreeSet<>(); // Display in order, I guess
		Set<AssemblyResolvedPatterns> misses = new TreeSet<>();
		for (AssemblyResolution ar : rr) {
			if (ar.isError()) {
				errs.add((AssemblyResolvedError) ar);
				continue;
			}
			AssemblyResolvedPatterns rescon = (AssemblyResolvedPatterns) ar;
			if (ins.getVals().length == rescon.getInstructionLength() &&
				ins.combine(rescon.getInstruction()) != null) {
				return;
			}
			misses.add(rescon);
		}
		fail("No result matched the desired instruction bytes");
	}

	/**
	 * Confirm that every non-erroneous resolution disassembles to the given text
	 *
	 * @param rr the collection of assembly resolutions
	 * @param disassembly the expected disassembly text
	 * @param addr the address of the instruction(s)
	 * @param ctxstr a string describing the input context pattern
	 * @see AssemblyPatternBlock#fromString(String)
	 */
	protected void checkAllExact(AssemblyResolutionResults rr,
			Collection<String> disassembly, long addr, String ctxstr) {
		Address address = lang.getDefaultSpace().getAddress(addr);
		final AssemblyPatternBlock ctx = (ctxstr == null ? context.getDefaultAt(address)
				: AssemblyPatternBlock.fromString(ctxstr)).fillMask();
		boolean gotOne = false;
		boolean failedOne = false;
		Set<AssemblyResolvedError> errs = new TreeSet<>(); // Display in order, I guess.
		MultiValuedMap<String, String> misTxtToCons = new TreeSetValuedTreeMap<>();
		MultiValuedMap<String, AssemblyResolvedPatterns> misTxtConsToRes =
			new TreeSetValuedTreeMap<>();
		for (AssemblyResolution ar : rr) {
			if (ar.isError()) {
				errs.add((AssemblyResolvedError) ar);
				continue;
			}
			AssemblyResolvedPatterns rp = (AssemblyResolvedPatterns) ar;
			try {
				for (byte[] ins : rp.possibleInsVals(ctx)) {
					PseudoInstruction pi = disassemble(addr, ins, ctx.getVals());
					String cons = dumpConstructorTree(pi);
					String dis = pi.toString();
					if (!disassembly.contains(dis.trim())) {
						failedOne = true;
						misTxtToCons.put(dis, cons);
						misTxtConsToRes.put(dis + cons, rp);
					}
					gotOne = true;
				}
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		if (failedOne) {
			fail("At least one result did not disassemble to the given text");
		}
		if (!gotOne) {
			fail("Did not get any matches");
		}
	}

	/**
	 * Confirm that every parse result describes an error, i.e., the text failed to parse.
	 *
	 * @param parse the collection of parse results
	 */
	protected void checkAllSyntaxErrs(Collection<AssemblyParseResult> parse) {
		for (AssemblyParseResult pr : parse) {
			if (!pr.isError()) {
				fail("All results were expected to be syntax errors.");
			}
		}
	}

	/**
	 * Confirm that every resolution result describes an error, i.e., the text failed to assemble
	 *
	 * @param res the collection of assembly resolutions
	 */
	protected void checkAllSemanticErrs(AssemblyResolutionResults res) {
		for (AssemblyResolution ar : res) {
			if (ar.isError()) {
				continue;
			}
			fail("All results were expected to be errors");
		}
	}

	/**
	 * A class which allows tests to attempt to gracefully handle changes in language modules.
	 * 
	 * If the expected assembly string does not match what disassembly of the expected bytes yields,
	 * this exception is thrown. This allows the test to provide an alternative expected assembly.
	 */
	protected static class DisassemblyMismatchException extends RuntimeException {
		DisassemblyMismatchException(String message) {
			super(message);
		}
	}

	/**
	 * Run a test with the given checks
	 *
	 * @param assembly the text to assemble
	 * @param instr an instruction pattern that must appear in the results
	 * @param disassembly a set of acceptable disassembly texts
	 * @param addr the address for assembly and disassembly
	 * @param ctxstr the context for assembly and disassembly
	 * @param checkOneCompat if {@code instr != null} check that one result matches it
	 * @param checkAllExact if {@code disassembly != null} check that all are acceptable
	 * @param checkAllSyntaxErrs confirm that {@code assembly} does not parse
	 * @param checkAllSemanticErrs confirm that {@code assembly} does not assemble
	 * @see AssemblyPatternBlock#fromString(String)
	 */
	protected void runTest(String assembly, String instr, Collection<String> disassembly, long addr,
			String ctxstr, boolean checkOneCompat, boolean checkAllExact,
			boolean checkAllSyntaxErrs, boolean checkAllSemanticErrs) {
		Address address = lang.getDefaultSpace().getAddress(addr);

		// A sanity check, first
		if (instr != null) {
			AssemblyPatternBlock ins = AssemblyPatternBlock.fromString(instr);
			if (!ins.isFullMask()) {
				throw new RuntimeException("Desired instruction bytes should be fully-defined");
			}
			final AssemblyPatternBlock ctx = (ctxstr == null ? context.getDefaultAt(address)
					: AssemblyPatternBlock.fromString(ctxstr)).fillMask();
			try {
				String disstr;
				PseudoInstruction psins = disassemble(addr, ins.getVals(), ctx.getVals());
				SleighInstructionPrototype sip = (SleighInstructionPrototype) psins.getPrototype();
				Msg.debug(this, "Expected tree: " + sip.dumpConstructorTree());
				disstr = psins.toString().trim();

				if (!disassembly.contains(disstr)) {
					throw new DisassemblyMismatchException(
						"Desired instruction bytes do not disassemble to a desired string: " +
							disassembly + "; found instead: " + disstr);
				}
			}
			catch (InsufficientBytesException | UnknownInstructionException
					| AddressOverflowException | MemoryAccessException e) {
				throw new RuntimeException("Cannot disassemble desired instruction bytes", e);
			}
		}

		Assembler assembler = Assemblers.getAssembler(lang, new AssemblySelector() {
			@Override
			public Collection<AssemblyParseResult> filterParse(
					Collection<AssemblyParseResult> parse) throws AssemblySyntaxException {
				AssemblyTestCase.dbgPrintTrees(parse);
				if (checkAllSyntaxErrs) {
					checkAllSyntaxErrs(parse);
				}
				return super.filterParse(parse);
			}

			@Override
			public Selection select(AssemblyResolutionResults rr, AssemblyPatternBlock ctx)
					throws AssemblySemanticException {
				if (checkOneCompat) {
					checkOneCompat(instr, rr);
				}
				if (checkAllExact) {
					checkAllExact(rr, disassembly, addr, ctxstr);
				}
				if (checkAllSemanticErrs) {
					checkAllSemanticErrs(rr);
				}
				return super.select(rr, ctx);
			}
		});

		try {
			if (ctxstr == null) {
				assembler.assembleLine(address, assembly);
			}
			else {
				SleighAssembler sas = (SleighAssembler) assembler;
				sas.assembleLine(address, assembly, AssemblyPatternBlock.fromString(ctxstr));
			}
		}
		catch (AssemblySemanticException e) {
			if (!checkAllSemanticErrs) {
				throw new AssertionError("There was an unexpected semantic error: " + e);
			}
		}
		catch (AssemblySyntaxException e) {
			if (!checkAllSyntaxErrs) {
				throw new AssertionError("There was an unexpected syntax error: " + e);
			}
		}
	}

	/**
	 * Run a test where one result must match a given instruction pattern, and all others must
	 * disassemble exactly to the input
	 * 
	 * @param assembly the input assembly
	 * @param instr the instruction pattern
	 * @see AssemblyPatternBlock#fromString(String)
	 */
	protected void assertOneCompatRestExact(String assembly, String instr) {
		runTest(assembly, instr, Collections.singleton(assembly), DEFAULT_ADDR, null, true, true,
			false, false);
	}

	/**
	 * Run a test where one result must match a given instruction pattern, and all others must
	 * disassemble to an acceptable result
	 *
	 * @param assembly the input assembly
	 * @param instr the instruction pattern
	 * @param disassemblies the set of acceptable disassemblies
	 * @see AssemblyPatternBlock#fromString(String)
	 */
	protected void assertOneCompatRestExact(String assembly, String instr,
			String... disassemblies) {
		Set<String> disasm = new HashSet<>(Arrays.asList(disassemblies));
		runTest(assembly, instr, disasm, DEFAULT_ADDR, null, true, true, false, false);
	}

	/**
	 * Like {@link #assertOneCompatRestExact(String, String)}, except the address is given
	 *
	 * @param assembly the input assembly
	 * @param instr the instruction pattern
	 * @param addr the address for assembly and disassembly
	 * @see AssemblyPatternBlock#fromString(String)
	 */
	protected void assertOneCompatRestExact(String assembly, String instr, long addr) {
		runTest(assembly, instr, Collections.singleton(assembly), addr, null, true, true, false,
			false);
	}

	/**
	 * Like {@link #assertOneCompatRestExact(String, String, long)}, except an alternative
	 * disassembly is given
	 *
	 * @param assembly the input assembly
	 * @param instr the instruction pattern
	 * @param addr the address for assembly and disassembly
	 * @param disassemblies the set of acceptable disassemblies
	 * @see AssemblyPatternBlock#fromString(String)
	 */
	protected void assertOneCompatRestExact(String assembly, String instr, long addr,
			String... disassemblies) {
		Set<String> disasm = new HashSet<>(Arrays.asList(disassemblies));
		runTest(assembly, instr, disasm, addr, null, true, true, false, false);
	}

	/**
	 * Like {@link #assertOneCompatRestExact(String, String, long, String)}, except a context is
	 * given
	 *
	 * @param assembly the input assembly
	 * @param instr the instruction pattern
	 * @param addr the address for assembly and disassembly
	 * @param ctxstr the context pattern for assembly and disassembly
	 * @param disassemblies the set of acceptable disassemblies
	 * @see AssemblyPatternBlock#fromString(String)
	 */
	protected void assertOneCompatRestExact(String assembly, String instr, String ctxstr, long addr,
			String... disassemblies) {
		Set<String> disasm = new HashSet<>(Arrays.asList(disassemblies));
		runTest(assembly, instr, disasm, addr, ctxstr, true, true, false, false);
	}

	/**
	 * Run a test checking that the given assembly does not parse
	 *
	 * @param assembly the input assembly
	 */
	protected void assertAllSyntaxErrors(String assembly) {
		runTest(assembly, null, null, DEFAULT_ADDR, null, false, false, true, false);
	}

	/**
	 * Run a test checking that the given assembly parses, but does not assemble
	 *
	 * @param assembly the input assembly
	 */
	protected void assertAllSemanticErrors(String assembly) {
		runTest(assembly, null, null, DEFAULT_ADDR, null, false, false, false, true);
	}

	/**
	 * Like {@link #assertAllSemanticErrors(String)}, but a context is given
	 *
	 * @param assembly the input assembly
	 * @param ctxstr the context pattern for assembly
	 * @see AssemblyPatternBlock#fromString(String)
	 */
	protected void assertAllSemanticErrors(String assembly, String ctxstr) {
		runTest(assembly, null, null, DEFAULT_ADDR, ctxstr, false, false, false, true);
	}
}
