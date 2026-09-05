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
package ghidra.program.emulation;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.Map;

import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class Aarch64ScalarMinMaxTest extends AbstractGhidraHeadlessIntegrationTest {
	private static final String ENTRY = "0x00400000";

	private static final Map<String, String> ENCODINGS = Map.ofEntries(
		Map.entry("fmin h0,h1,h0", "20 58 e0 1e"),
		Map.entry("fmin s0,s1,s0", "20 58 20 1e"),
		Map.entry("fmin d0,d1,d0", "20 58 60 1e"),
		Map.entry("fmax h0,h1,h0", "20 48 e0 1e"),
		Map.entry("fmax s0,s1,s0", "20 48 20 1e"),
		Map.entry("fmax d0,d1,d0", "20 48 60 1e"),
		Map.entry("fmaxnm h0,h1,h0", "20 68 e0 1e"),
		Map.entry("fmaxnm s0,s1,s0", "20 68 20 1e"),
		Map.entry("fmaxnm d0,d1,d0", "20 68 60 1e"),
		Map.entry("fmin s0,s1,s2", "20 58 22 1e"),
		Map.entry("fmax s0,s1,s2", "20 48 22 1e"),
		Map.entry("fmin s0,s0,s1", "00 58 21 1e"));

	private static final String F16_ONE = "3c00";
	private static final String F16_TWO = "4000";
	private static final String F32_ONE = "3f800000";
	private static final String F32_TWO = "40000000";
	private static final String F64_ONE = "3ff0000000000000";
	private static final String F64_TWO = "4000000000000000";

	private void assertResultIsInitialValueOf(String assembly, Map<String, String> initialState,
			String winningRegister) throws Exception {
		String resultRegister = assembly.substring(assembly.indexOf(' ') + 1).split(",")[0].trim();
		String expected = initialState.get(winningRegister);
		assertNotNull(winningRegister + " has no initial value in " + assembly, expected);
		String encoding = ENCODINGS.get(assembly);
		assertNotNull("no encoding recorded for " + assembly, encoding);

		ProgramBuilder builder = new ProgramBuilder("minmax", ProgramBuilder._AARCH64);
		try {
			builder.setBytes(ENTRY, encoding);
			builder.disassemble(ENTRY, 4);

			Program program = builder.getProgram();
			SleighLanguage language = (SleighLanguage) program.getLanguage();
			Instruction instruction = program.getListing().getInstructionAt(builder.addr(ENTRY));
			assertNotNull("nothing decoded from " + encoding, instruction);
			assertEquals(encoding, assembly, instruction.toString());

			BytesPcodeExecutorState state =
				new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
			PcodeArithmetic<byte[]> arithmetic = state.getArithmetic();
			PcodeExecutor<byte[]> executor = new PcodeExecutor<>(state, Reason.EXECUTE_READ);

			for (Map.Entry<String, String> entry : initialState.entrySet()) {
				Register register = language.getRegister(entry.getKey());
				state.setVar(register, arithmetic.fromConst(new BigInteger(entry.getValue(), 16),
					register.getNumBytes()));
			}

			executor.execute(PcodeProgram.fromInstruction(instruction), PcodeUseropLibrary.nil());

			Register result = language.getRegister(resultRegister);
			assertEquals(assembly + ": " + resultRegister + " should hold the initial " +
				winningRegister, expected,
				arithmetic.toBigInteger(state.getVar(result, Reason.INSPECT), Purpose.INSPECT)
						.toString(16));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testAliasedMinimumKeepsTheDestinationOperand() throws Exception {
		assertResultIsInitialValueOf("fmin h0,h1,h0", Map.of("h0", F16_ONE, "h1", F16_TWO), "h0");
		assertResultIsInitialValueOf("fmin s0,s1,s0", Map.of("s0", F32_ONE, "s1", F32_TWO), "s0");
		assertResultIsInitialValueOf("fmin d0,d1,d0", Map.of("d0", F64_ONE, "d1", F64_TWO), "d0");
	}

	@Test
	public void testAliasedMaximumKeepsTheDestinationOperand() throws Exception {
		assertResultIsInitialValueOf("fmax h0,h1,h0", Map.of("h0", F16_TWO, "h1", F16_ONE), "h0");
		assertResultIsInitialValueOf("fmax s0,s1,s0", Map.of("s0", F32_TWO, "s1", F32_ONE), "s0");
		assertResultIsInitialValueOf("fmax d0,d1,d0", Map.of("d0", F64_TWO, "d1", F64_ONE), "d0");
	}

	@Test
	public void testAliasedMaximumNumberKeepsTheDestinationOperand() throws Exception {
		assertResultIsInitialValueOf("fmaxnm h0,h1,h0", Map.of("h0", F16_TWO, "h1", F16_ONE), "h0");
		assertResultIsInitialValueOf("fmaxnm s0,s1,s0", Map.of("s0", F32_TWO, "s1", F32_ONE), "s0");
		assertResultIsInitialValueOf("fmaxnm d0,d1,d0", Map.of("d0", F64_TWO, "d1", F64_ONE), "d0");
	}

	@Test
	public void testAliasedMinimumKeepsTheSourceOperand() throws Exception {
		assertResultIsInitialValueOf("fmin h0,h1,h0", Map.of("h0", F16_TWO, "h1", F16_ONE), "h1");
		assertResultIsInitialValueOf("fmin s0,s1,s0", Map.of("s0", F32_TWO, "s1", F32_ONE), "s1");
		assertResultIsInitialValueOf("fmin d0,d1,d0", Map.of("d0", F64_TWO, "d1", F64_ONE), "d1");
	}

	@Test
	public void testAliasedMaximumKeepsTheSourceOperand() throws Exception {
		assertResultIsInitialValueOf("fmax h0,h1,h0", Map.of("h0", F16_ONE, "h1", F16_TWO), "h1");
		assertResultIsInitialValueOf("fmax s0,s1,s0", Map.of("s0", F32_ONE, "s1", F32_TWO), "s1");
		assertResultIsInitialValueOf("fmax d0,d1,d0", Map.of("d0", F64_ONE, "d1", F64_TWO), "d1");
	}

	@Test
	public void testAliasedMaximumNumberKeepsTheSourceOperand() throws Exception {
		assertResultIsInitialValueOf("fmaxnm h0,h1,h0", Map.of("h0", F16_ONE, "h1", F16_TWO), "h1");
		assertResultIsInitialValueOf("fmaxnm s0,s1,s0", Map.of("s0", F32_ONE, "s1", F32_TWO), "s1");
		assertResultIsInitialValueOf("fmaxnm d0,d1,d0", Map.of("d0", F64_ONE, "d1", F64_TWO), "d1");
	}

	@Test
	public void testThreeDistinctRegisters() throws Exception {
		assertResultIsInitialValueOf("fmin s0,s1,s2", Map.of("s1", F32_TWO, "s2", F32_ONE), "s2");
		assertResultIsInitialValueOf("fmin s0,s1,s2", Map.of("s1", F32_ONE, "s2", F32_TWO), "s1");
		assertResultIsInitialValueOf("fmax s0,s1,s2", Map.of("s1", F32_TWO, "s2", F32_ONE), "s1");
		assertResultIsInitialValueOf("fmax s0,s1,s2", Map.of("s1", F32_ONE, "s2", F32_TWO), "s2");
	}

	@Test
	public void testDestinationAliasingTheFirstSource() throws Exception {
		assertResultIsInitialValueOf("fmin s0,s0,s1", Map.of("s0", F32_TWO, "s1", F32_ONE), "s1");
		assertResultIsInitialValueOf("fmin s0,s0,s1", Map.of("s0", F32_ONE, "s1", F32_TWO), "s0");
	}
}
