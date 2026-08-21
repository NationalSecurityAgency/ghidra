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
import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.JitPassage.ExitPcodeOp;
import ghidra.pcode.emu.jit.analysis.JitAnalysisContext;
import ghidra.pcode.emu.jit.decode.JitPassageDecoderTestAccess;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class AbstractJitTest extends AbstractGTest {

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

	/**
	 * Generate a p-code program from the given instruction sequence
	 * 
	 * <p>
	 * The instructions are considered in list order, regardless of their addresses. The caller must
	 * ensure the order is consistent. An empty instruction list is not allowed, and all
	 * instructions must be from the same Sleigh language.
	 * 
	 * <p>
	 * If there are gaps with fall-through a special {@link ExitPcodeOp} is inserted that, if
	 * executed blindly, would result in an infinite loop. The intent here is to cue the executor to
	 * abandon this program and re-visit the decoder for further ops.
	 * 
	 * <p>
	 * An entry address must be given, because the lowest address instruction is not necessarily the
	 * entry point, but must appear first in the list. If the given entry is not the lowest address,
	 * this will insert a {@link PcodeOp#BRANCH} op at the start to ensure control is immediately
	 * given to the specified entry.
	 * 
	 * @param instructions the instructions
	 * @param entry the address of the first instruction to execute
	 * @return the p-code program
	 */
	public static JitPassage makePassageFromInstructions(Iterable<Instruction> instructions,
			AddrCtx entry) {
		return Unfinished.TODO("Don't use this");
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
			new JitConfiguration(), MethodHandles.lookup());
		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		JitPcodeThread thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());
		return decodePassage(thread);
	}
}
