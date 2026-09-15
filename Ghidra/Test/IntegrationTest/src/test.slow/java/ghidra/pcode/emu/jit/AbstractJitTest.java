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
package ghidra.pcode.emu.jit;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.lang.invoke.MethodHandles;

import org.junit.Before;

import generic.test.AbstractGTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.assembler.AssemblyBuffer;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.pcode.emu.jit.analysis.JitAnalysisContext;
import ghidra.pcode.emu.jit.decode.JitPassageDecoderTestAccess;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.pcode.PcodeOp;

public class AbstractJitTest extends AbstractGTest {

	protected JitConfiguration createConfiguration() {
		return new JitConfiguration();
	}

	public static PcodeOp assertOp(int opcode, PcodeOp op) {
		assertEquals(opcode, op.getOpcode());
		return op;
	}

	@Before
	public void setUp() throws IOException {
		if (!Application.isInitialized()) {
			Application.initializeApplication(
				new GhidraTestApplicationLayout(new File(getTestDirectoryPath())),
				new ApplicationConfiguration());
		}
	}

	public static JitPassage makePassageFromPcode(PcodeProgram program, JitPcodeThread thread) {
		if (program instanceof JitPassage passage) {
			return passage;
		}
		return JitPassageDecoderTestAccess.simulateFromPcode(program, thread);
	}

	public static JitAnalysisContext makeContext(SleighLanguage language, String sleigh,
			PcodeUseropLibrary<?> library) {
		@SuppressWarnings("unchecked")
		final PcodeUseropLibrary<byte[]> myLib = (PcodeUseropLibrary<byte[]>) library;
		JitPcodeEmulator emu = new JitPcodeEmulator(language, new JitConfiguration(),
			MethodHandles.publicLookup()) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return super.createUseropLibrary().compose(myLib);
			}
		};
		JitPcodeThread thread = emu.newThread();
		PcodeProgram program = emu.compileSleigh("test", sleigh);
		return makeContext(program, thread);
	}

	public static JitAnalysisContext makeContext(PcodeProgram program) {
		JitPcodeEmulator emu = new JitPcodeEmulator(program.getLanguage(), new JitConfiguration(),
			MethodHandles.publicLookup());
		JitPcodeThread thread = emu.newThread();
		return makeContext(program, thread);
	}

	public static JitAnalysisContext makeContext(PcodeProgram program,
			JitConfiguration config) {
		JitPcodeEmulator emu =
			new JitPcodeEmulator(program.getLanguage(), config, MethodHandles.publicLookup());
		JitPcodeThread thread = emu.newThread();
		return makeContext(program, thread);
	}

	public static JitAnalysisContext makeContext(PcodeProgram program, JitPcodeThread thread) {
		return new JitAnalysisContext(thread.getMachine().getConfiguration(),
			makePassageFromPcode(program, thread));
	}

	public JitPassage decodePassage(JitPcodeThread thread) {
		int maxOps = thread.getMachine().getConfiguration().maxPassageOps();
		return thread.passageDecoder.decodePassage(thread.getCounter(), thread.getContext(),
			maxOps);
	}

	public JitPassage decodePassage(AssemblyBuffer asm) {
		JitPcodeEmulator emu = new JitPcodeEmulator(asm.getAssembler().getLanguage(),
			createConfiguration(), MethodHandles.lookup());
		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		JitPcodeThread thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());
		return decodePassage(thread);
	}
}
