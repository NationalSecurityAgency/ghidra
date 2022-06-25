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
package ghidra.pcode.exec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.util.List;

import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class AnnotatedPcodeUseropLibraryTest extends AbstractGhidraHeadlessIntegrationTest {
	private class TestUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
		@Override
		protected Lookup getMethodLookup() {
			return MethodHandles.lookup();
		}
	}

	protected PcodeExecutor<byte[]> createBytesExecutor() throws Exception {
		return createBytesExecutor("Toy:BE:64:default");
	}

	protected PcodeExecutor<byte[]> createBytesExecutor(String languageId) throws Exception {
		SleighLanguage language =
			(SleighLanguage) getLanguageService().getLanguage(new LanguageID(languageId));
		PcodeExecutorState<byte[]> state = new BytesPcodeExecutorState(language);
		PcodeArithmetic<byte[]> arithmetic = BytesPcodeArithmetic.forLanguage(language);
		return new PcodeExecutor<>(language, arithmetic, state);
	}

	protected <T> void executeSleigh(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library,
			String... lines) {
		PcodeProgram program = SleighProgramCompiler.compileProgram(executor.getLanguage(), "test",
			List.of(lines), library);
		executor.execute(program, library);
	}

	protected void executeSleigh(PcodeUseropLibrary<byte[]> library, String... lines)
			throws Exception {
		executeSleigh(createBytesExecutor(), library, lines);
	}

	protected static void assertBytes(long expectedVal, int expectedSize, byte[] actual) {
		assertEquals(expectedSize, actual.length);
		assertEquals(expectedVal, Utils.bytesToLong(actual, expectedSize, true));
	}

	protected static void assertConstVarnode(long expectedVal, int expectedSize, Varnode actual) {
		assertTrue(actual.getAddress().isConstantAddress());
		assertEquals(expectedVal, actual.getOffset());
		assertEquals(expectedSize, actual.getSize());
	}

	protected static void assertRegVarnode(Register expected, Varnode actual) {
		assertEquals(expected.getAddress(), actual.getAddress());
		assertEquals(expected.getNumBytes(), actual.getSize());
	}

	@Test
	public void testNoParams() throws Exception {
		var library = new TestUseropLibrary() {
			boolean invoked = false;

			@PcodeUserop
			private void __testop() {
				invoked = true;
			}
		};

		executeSleigh(library, "__testop();");
		assertTrue(library.invoked);
	}

	@Test
	public void testOneInputFixedT() throws Exception {
		var library = new TestUseropLibrary() {
			byte[] input;

			@PcodeUserop
			private void __testop(byte[] input) {
				this.input = input;
			}
		};

		executeSleigh(library, "__testop(1234:4);");
		assertBytes(1234, 4, library.input);
	}

	@Test
	public void testVariadicInputT() throws Exception {
		var library = new TestUseropLibrary() {
			byte[][] inputs;

			@PcodeUserop(variadic = true)
			private void __testop(byte[][] inputs) {
				this.inputs = inputs;
			}
		};

		executeSleigh(library, "__testop(1234:4, 4567:2);");
		assertBytes(1234, 4, library.inputs[0]);
		assertBytes(4567, 2, library.inputs[1]);
	}

	@Test
	public void testVariadicInputVars() throws Exception {
		var library = new TestUseropLibrary() {
			Varnode[] inputs;

			@PcodeUserop(variadic = true)
			private void __testop(Varnode[] inputs) {
				this.inputs = inputs;
			}
		};

		executeSleigh(library, "__testop(1234:4, 4567:2);");
		assertConstVarnode(1234, 4, library.inputs[0]);
		assertConstVarnode(4567, 2, library.inputs[1]);
	}

	@Test
	public void testReturnedOutput() throws Exception {
		var library = new TestUseropLibrary() {
			@PcodeUserop
			private byte[] __testop() {
				return Utils.longToBytes(1234, 8, true);
			}
		};

		PcodeExecutor<byte[]> executor = createBytesExecutor();
		Register r0 = executor.getLanguage().getRegister("r0");

		executeSleigh(executor, library, "r0 = __testop();");
		assertBytes(1234, 8, executor.getState().getVar(r0));
	}

	@Test
	public void testReturnedOutputBinaryFunc() throws Exception {
		var library = new TestUseropLibrary() {
			@PcodeUserop
			private byte[] __testop(byte[] aBytes, byte[] bBytes) {
				long a = Utils.bytesToLong(aBytes, 8, true);
				long b = Utils.bytesToLong(bBytes, 8, true);
				return Utils.longToBytes(a * a + b, 8, true);
			}
		};

		PcodeExecutor<byte[]> executor = createBytesExecutor();
		Register r0 = executor.getLanguage().getRegister("r0");
		Register r1 = executor.getLanguage().getRegister("r1");

		executor.getState().setVar(r0, Utils.longToBytes(10, 8, true));
		executeSleigh(executor, library, "r1 = __testop(r0, 59:8);");
		assertBytes(159, 8, executor.getState().getVar(r1));
	}

	@Test
	public void testOpExecutor() throws Exception {
		var library = new TestUseropLibrary() {
			PcodeExecutor<byte[]> executor;

			@PcodeUserop
			private void __testop(@OpExecutor PcodeExecutor<byte[]> executor) {
				this.executor = executor;
			}
		};

		PcodeExecutor<byte[]> executor = createBytesExecutor();
		executeSleigh(executor, library, "__testop();");
		assertEquals(executor, library.executor);
	}

	@Test
	public void testOpState() throws Exception {
		var library = new TestUseropLibrary() {
			PcodeExecutorStatePiece<byte[], byte[]> state;

			@PcodeUserop
			private void __testop(@OpState PcodeExecutorStatePiece<byte[], byte[]> state) {
				this.state = state;
			}
		};

		PcodeExecutor<byte[]> executor = createBytesExecutor();
		executeSleigh(executor, library, "__testop();");
		assertEquals(executor.getState(), library.state);
	}

	@Test
	public void testOpLibrary() throws Exception {
		var library = new TestUseropLibrary() {
			PcodeUseropLibrary<byte[]> lib;

			@PcodeUserop
			private void __testop(@OpLibrary PcodeUseropLibrary<byte[]> lib) {
				this.lib = lib;
			}
		};

		PcodeExecutor<byte[]> executor = createBytesExecutor();
		executeSleigh(executor, library, "__testop();");
		assertEquals(library, library.lib);
	}

	@Test
	public void testOpOutput() throws Exception {
		var library = new TestUseropLibrary() {
			Varnode outVar;

			@PcodeUserop
			private void __testop(@OpOutput Varnode outVar) {
				this.outVar = outVar;
			}
		};

		PcodeExecutor<byte[]> executor = createBytesExecutor();
		Register r0 = executor.getLanguage().getRegister("r0");
		executeSleigh(executor, library, "r0 = __testop();");
		assertRegVarnode(r0, library.outVar);
	}

	@Test
	public void testKitchenSink() throws Exception {
		var library = new TestUseropLibrary() {
			PcodeExecutor<byte[]> executor;
			PcodeExecutorStatePiece<byte[], byte[]> state;
			PcodeUseropLibrary<byte[]> lib;
			Varnode outVar;
			Varnode inVar0;
			byte[] inVal1;

			@PcodeUserop
			private byte[] __testop(
					@OpOutput Varnode outVar,
					@OpLibrary PcodeUseropLibrary<byte[]> lib,
					@OpExecutor PcodeExecutor<byte[]> executor,
					Varnode inVar0,
					@OpState PcodeExecutorStatePiece<byte[], byte[]> state,
					byte[] inVal1) {
				this.executor = executor;
				this.state = state;
				this.lib = lib;
				this.outVar = outVar;
				this.inVar0 = inVar0;
				this.inVal1 = inVal1;

				return inVal1;
			}
		};

		PcodeExecutor<byte[]> executor = createBytesExecutor();
		Register r0 = executor.getLanguage().getRegister("r0");
		Register r1 = executor.getLanguage().getRegister("r1");
		executeSleigh(executor, library, "r0 = __testop(r1, 1234:8);");
		assertEquals(executor, library.executor);
		assertEquals(executor.getState(), library.state);
		assertEquals(library, library.lib);
		assertRegVarnode(r0, library.outVar);
		assertRegVarnode(r1, library.inVar0);
		assertBytes(1234, 8, library.inVal1);
		assertBytes(1234, 8, executor.getState().getVar(r0));
	}

	@Test(expected = SleighException.class)
	public void testErrNotExported() throws Exception {
		var library = new TestUseropLibrary() {
			@SuppressWarnings("unused")
			private void __testop() {
			}
		};

		executeSleigh(library, "r0 = __testop();");
	}

	@Test(expected = PcodeExecutionException.class)
	public void testErrParameterCountMismatch() throws Exception {
		var library = new TestUseropLibrary() {
			@PcodeUserop
			private void __testop(Varnode in0) {
			}
		};

		executeSleigh(library, "r0 = __testop();");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrAccess() throws Exception {
		new AnnotatedPcodeUseropLibrary<byte[]>() {
			@PcodeUserop
			private void __testop(Varnode in0) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrReturnType() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop
			private int __testop() {
				return 0;
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrInputType() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop
			private void __testop(int in0) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrExecutorType() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop
			private void __testop(@OpExecutor int executor) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrStateType() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop
			private void __testop(@OpState int state) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrOutputType() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop
			private void __testop(@OpOutput int out) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrVariadicInputsType() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop(variadic = true)
			private void __testop(int[] ins) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrConflictingAnnotations() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop
			private void __testop(@OpExecutor @OpState int in0) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrDuplicateExecutor() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop
			private void __testop(@OpExecutor PcodeExecutor<byte[]> executor0,
					@OpExecutor PcodeExecutor<byte[]> executor1) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrDuplicateState() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop
			private void __testop(@OpState PcodeExecutorStatePiece<byte[], byte[]> state0,
					@OpState PcodeExecutorStatePiece<byte[], byte[]> state1) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrDuplicateOutput() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop
			private void __testop(@OpOutput Varnode out0, @OpOutput Varnode out1) {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrMissingVariadicInputs() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop(variadic = true)
			private void __testop() {
			}
		};
	}

	@Test(expected = IllegalArgumentException.class)
	public void testErrDuplicateVariadicInputs() throws Exception {
		new TestUseropLibrary() {
			@PcodeUserop(variadic = true)
			private void __testop(Varnode[] ins0, Varnode[] ins1) {
			}
		};
	}

}
