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
package ghidra.pcode.exec.trace;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;

public class TraceSleighUtilsTest extends AbstractGhidraHeadlessIntegrationTest {
	private static final String TOY_BE_64_HARVARD = "Toy:BE:64:harvard";

	SleighLanguage language;

	@Before
	public void setUp() throws LanguageNotFoundException {
		language = (SleighLanguage) DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID(TOY_BE_64_HARVARD));
	}

	@Test
	public void testConstant() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			assertEquals(BigInteger.valueOf(1234),
				TraceSleighUtils.evaluate("1234:2", b.trace, 0, null, 0));
		}
	}

	@Test
	public void testConstantWithState() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			assertEquals(Map.entry(BigInteger.valueOf(1234), TraceMemoryState.KNOWN),
				TraceSleighUtils.evaluateWithState("1234:2", b.trace, 0, null, 0));
		}
	}

	@Test
	public void testRegister() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			TraceThread thread;
			try (UndoableTransaction tid = b.startTransaction()) {
				thread = b.getOrAddThread("Thread1", 0);

				Register r0 = language.getRegister("r0");
				TraceMemoryRegisterSpace regs =
					b.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(0, new RegisterValue(r0, BigInteger.valueOf(4321)));
			}

			assertEquals(BigInteger.valueOf(4321),
				TraceSleighUtils.evaluate("r0", b.trace, 0, thread, 0));
		}
	}

	@Test
	public void testMemory() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			try (UndoableTransaction tid = b.startTransaction()) {
				b.trace.getMemoryManager().putBytes(0, b.addr(0x00400000), b.buf(1, 2, 3, 4));
			}

			assertEquals(BigInteger.valueOf(0x01020304),
				TraceSleighUtils.evaluate("*:4 0x00400000:8", b.trace, 0, null, 0));
		}
	}

	@Test
	public void testBigMemory() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			try (UndoableTransaction tid = b.startTransaction()) {
				b.trace.getMemoryManager().putBytes(0, b.addr(0x00400000), b.buf(1, 2, 3, 4));
			}

			byte[] expected = new byte[1024];
			System.arraycopy(new byte[] { 1, 2, 3, 4 }, 0, expected, 0, 4);
			assertArrayEquals(expected,
				TraceSleighUtils.evaluateBytes("*:1024 0x00400000:8", b.trace, 0, null, 0));
		}
	}

	@Test
	public void testRegDeref() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			TraceThread thread;
			try (UndoableTransaction tid = b.startTransaction()) {
				thread = b.getOrAddThread("Thread1", 0);

				Register r0 = language.getRegister("r0");
				TraceMemoryRegisterSpace regs =
					b.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(0, new RegisterValue(r0, BigInteger.valueOf(0x00400000)));

				b.trace.getMemoryManager().putBytes(0, b.addr(0x00400000), b.buf(1, 2, 3, 4));
			}

			assertEquals(BigInteger.valueOf(0x01020304),
				TraceSleighUtils.evaluate("*:4 r0", b.trace, 0, thread, 0));
		}
	}

	@Test
	public void testDoubleDeref() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			TraceThread thread;
			try (UndoableTransaction tid = b.startTransaction()) {
				thread = b.getOrAddThread("Thread1", 0);

				Register r0 = language.getRegister("r0");
				TraceMemoryRegisterSpace regs =
					b.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(0, new RegisterValue(r0, BigInteger.valueOf(0x00400000)));

				b.trace.getMemoryManager()
						.putBytes(0, b.addr(0x00400000), b.buf(0, 0, 0, 0, 0, 0x50, 0, 0));
				b.trace.getMemoryManager()
						.putBytes(0, b.addr(0x00500000), b.buf(1, 2, 3, 4));
			}

			assertEquals(BigInteger.valueOf(0x01020304),
				TraceSleighUtils.evaluate("*:4 (*:8 r0)", b.trace, 0, thread, 0));
		}
	}

	@Test
	public void testDoubleDerefWithState() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			TraceThread thread;
			try (UndoableTransaction tid = b.startTransaction()) {
				thread = b.getOrAddThread("Thread1", 0);

				Register r0 = language.getRegister("r0");
				TraceMemoryRegisterSpace regs =
					b.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(0, new RegisterValue(r0, BigInteger.valueOf(0x00400000)));

				b.trace.getMemoryManager()
						.putBytes(0, b.addr(0x00400000), b.buf(0, 0, 0, 0, 0, 0x50, 0, 0));
				b.trace.getMemoryManager()
						.putBytes(0, b.addr(0x00500000), b.buf(1, 2, 3, 4));
				b.trace.getMemoryManager()
						.putBytes(1, b.addr(0x00500000), b.buf(1, 2, 3, 4));
			}

			assertEquals(Map.entry(BigInteger.valueOf(0x01020304), TraceMemoryState.KNOWN),
				TraceSleighUtils.evaluateWithState("*:4 (*:8 r0)", b.trace, 0, thread, 0));

			// First deref (actually the register value) is unknown
			// Thus whole result should be unknown
			assertEquals(Map.entry(BigInteger.valueOf(0x01020304), TraceMemoryState.UNKNOWN),
				TraceSleighUtils.evaluateWithState("*:4 (*:8 r0)", b.trace, 1, thread, 0));
		}
	}

	@Test
	public void testDerefData() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			TraceThread thread;
			try (UndoableTransaction tid = b.startTransaction()) {
				thread = b.getOrAddThread("Thread1", 0);

				Register r0 = language.getRegister("r0");
				TraceMemoryRegisterSpace regs =
					b.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
				regs.setValue(0, new RegisterValue(r0, BigInteger.valueOf(0x00400000)));

				b.trace.getMemoryManager()
						.putBytes(0, b.addr(0x00400000), b.buf(0, 0, 0, 0, 0, 0x50, 0, 0));
				b.trace.getMemoryManager()
						.putBytes(0, b.data(0x00500000), b.buf(1, 2, 3, 4));
			}

			assertEquals(BigInteger.valueOf(0x01020304),
				TraceSleighUtils.evaluate("*[data]:4 (*:8 r0)", b.trace, 0, thread, 0));
		}
	}

	@Test
	public void testCompileSleighProgram() throws Exception {
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder("test", TOY_BE_64_HARVARD)) {
			PcodeProgram sp = SleighProgramCompiler.compileProgram((SleighLanguage) b.language,
				"test", List.of(
					"if (r0) goto <else>;",
					"    r1 = 6;",
					"    goto <done>;",
					"<else>",
					"    r1 = 7;",
					"<done>"),
				SleighUseropLibrary.NIL);
			TraceThread thread;
			try (UndoableTransaction tid = b.startTransaction()) {
				thread = b.getOrAddThread("Thread1", 0);
				PcodeExecutor<byte[]> executor =
					new PcodeExecutor<>(sp.getLanguage(),
						BytesPcodeArithmetic.forLanguage(b.language),
						new TraceBytesPcodeExecutorState(b.trace, 0, thread, 0));
				sp.execute(executor, SleighUseropLibrary.nil());
			}

			Register r1 = b.language.getRegister("r1");
			assertEquals(BigInteger.valueOf(6),
				b.trace.getMemoryManager()
						.getMemoryRegisterSpace(thread, false)
						.getValue(0, r1)
						.getUnsignedValue());
		}
	}
}
