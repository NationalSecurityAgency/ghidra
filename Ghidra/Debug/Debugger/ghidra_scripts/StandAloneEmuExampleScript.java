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
//An example emulation script that uses a stand-alone emulator.
//It provides the set-up code and then demonstrates some use cases.
//@author 
//@category Emulation
//@keybinding
//@menupath
//@toolbar

import java.nio.charset.Charset;

import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;

public class StandAloneEmuExampleScript extends GhidraScript {
	private final static Charset UTF8 = Charset.forName("utf8");
	private SleighLanguage language;
	private PcodeEmulator emulator;

	@Override
	protected void run() throws Exception {
		/*
		 * Create an emulator and start a thread
		 */
		language = (SleighLanguage) getLanguage(new LanguageID("x86:LE:64:default"));
		emulator = new PcodeEmulator(language) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return new DemoPcodeUseropLibrary(language, StandAloneEmuExampleScript.this);
			}

			// Uncomment this to see instructions printed as they are decoded
			/*
			protected BytesPcodeThread createThread(String name) {
				return new BytesPcodeThread(name, this) {
					@Override
					protected SleighInstructionDecoder createInstructionDecoder(
							PcodeExecutorState<byte[]> sharedState) {
						return new SleighInstructionDecoder(language, sharedState) {
							@Override
							public Instruction decodeInstruction(Address address,
									RegisterValue context) {
								Instruction instruction = super.decodeInstruction(address, context);
								println("Decoded " + address + ": " + instruction);
								return instruction;
							}
						};
					}
				};
			}
			*/
		};
		PcodeThread<byte[]> thread = emulator.newThread();
		// The emulator composes the full library for each thread
		PcodeUseropLibrary<byte[]> library = thread.getUseropLibrary();
		AddressSpace dyn = language.getDefaultSpace();

		/*
		 * Assemble a little test program and write it into the emulator
		 * 
		 * We're not really going to implement system calls here. We're just using it to demonstrate
		 * the implementation of a language-defined userop.
		 */
		Address entry = dyn.getAddress(0x00400000);
		Assembler asm = Assemblers.getAssembler(language);
		AssemblyBuffer buffer = new AssemblyBuffer(asm, entry);
		buffer.assemble("MOV RCX, 0xdeadbeef");
		Address injectHere = buffer.getNext();
		buffer.assemble("MOV RAX, 1");
		buffer.assemble("SYSCALL");
		buffer.assemble("MOV RAX, 2"); // Induce the interrupt we need to terminate
		buffer.assemble("SYSCALL");
		byte[] code = buffer.getBytes();
		emulator.getSharedState().setVar(dyn, entry.getOffset(), code.length, true, code);

		/*
		 * Initialize other parts of the emulator and thread state. Note the use of the L suffix on
		 * 0xdeadbeefL, because Java with sign extend the (negative) int to a long otherwise.
		 */
		byte[] hw = "Hello, World!\n".getBytes(UTF8);
		emulator.getSharedState().setVar(dyn, 0xdeadbeefL, hw.length, true, hw);
		PcodeProgram init = SleighProgramCompiler.compileProgram(language, "init", String.format("""
				RIP = 0x%s;
				RSP = 0x00001000;
				""", entry), library);
		thread.getExecutor().execute(init, library);
		thread.overrideContextWithDefault();
		thread.reInitialize();

		/*
		 * Inject a call to our custom print userop. Otherwise, the language itself will never
		 * invoke it.
		 */
		emulator.inject(injectHere, """
				print_utf8(RCX);
				emu_exec_decoded();
				""");

		/*
		 * Run the experiment: This should interrupt on the second SYSCALL, because any value other
		 * than 1 calls emu_swi.
		 */
		try {
			thread.stepInstruction(10);
			printerr("We should not have completed 10 steps!");
		}
		catch (InterruptPcodeExecutionException e) {
			println("Terminated via interrupt. Good.");
		}

		/*
		 * Inspect the machine. You can always do this by accessing the state directly, but for
		 * anything other than simple variables, you may find compiling an expression more
		 * convenient.
		 */
		println("RCX = " +
			Utils.bytesToLong(thread.getState().getVar(language.getRegister("RCX"), Reason.INSPECT),
				8, language.isBigEndian()));

		println("RCX = " + Utils.bytesToLong(
			SleighProgramCompiler.compileExpression(language, "RCX").evaluate(thread.getExecutor()),
			8, language.isBigEndian()));

		println("RCX+4 = " +
			Utils.bytesToLong(SleighProgramCompiler.compileExpression(language, "RCX+4")
					.evaluate(thread.getExecutor()),
				8, language.isBigEndian()));
	}
}
