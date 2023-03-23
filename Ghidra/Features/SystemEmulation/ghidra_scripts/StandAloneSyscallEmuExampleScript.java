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
//An example emulation script that uses a stand-alone emulator with syscalls.
//It provides the set-up code and then demonstrates some use cases.
//@author 
//@category Emulation
//@keybinding
//@menupath
//@toolbar

import java.nio.charset.Charset;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.sys.EmuInvalidSystemCallException;
import ghidra.pcode.emu.sys.EmuSyscallLibrary;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class StandAloneSyscallEmuExampleScript extends GhidraScript {
	private final static Charset UTF8 = Charset.forName("utf8");

	Program program = null;

	@Override
	protected void run() throws Exception {
		/*
		 * First, get all the services and stuff:
		 */
		SleighLanguage language = (SleighLanguage) getLanguage(new LanguageID("x86:LE:64:default"));

		/*
		 * I'll generate a new program, because I don't want to require the user to pick something
		 * specific. It won't be displayed, though, so we'll just release it when we're done.
		 */
		Address entry;
		try {
			/*
			 * "gcc" is the name of the compiler spec, but we're really interested in the Linux
			 * syscall calling conventions.
			 */
			program =
				new ProgramDB("syscall_example", language,
					language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
			try (Transaction tx = program.openTransaction("Init")) {
				AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
				entry = space.getAddress(0x00400000);
				Address dataEntry = space.getAddress(0x00600000);
				Memory memory = program.getMemory();
				memory.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
				Assembler asm = Assemblers.getAssembler(program);
				asm.assemble(entry,
					"MOV RDI, 0x" + dataEntry,
					"MOV RAX, 1",
					"SYSCALL",
					"MOV RAX, 20",
					"SYSCALL");
				memory.createInitializedBlock(".data", dataEntry, 0x1000, (byte) 0, monitor, false);
				memory.setBytes(dataEntry, "Hello, World!\n".getBytes(UTF8));

				/*
				 * Because "pointer" is a built-in type, and the emulator does not modify the
				 * program, we must ensure it has been resolved on the program's data type manager.
				 */
				program.getDataTypeManager()
						.resolve(PointerDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);

				/*
				 * We must also populate the system call numbering map. Ordinarily, this would be done
				 * using the system call analyzer or another script. Here, we'll just fake it out.
				 */
				AddressSpace other =
					program.getAddressFactory().getAddressSpace(SpaceNames.OTHER_SPACE_NAME);
				MemoryBlock blockSyscall = program.getMemory()
						.createUninitializedBlock(EmuSyscallLibrary.SYSCALL_SPACE_NAME,
							other.getAddress(0), 0x1000, true);
				blockSyscall.setPermissions(true, false, true);

				AddressSpace syscall = program.getAddressFactory()
						.getAddressSpace(EmuSyscallLibrary.SYSCALL_SPACE_NAME);
				/*
				 * The system call names must match those from the EmuSyscall annotations in the
				 * system call library, in our case from DemoSyscallLibrary. Because the x64
				 * compiler specs define a "syscall" convention, we'll apply it. The syscall
				 * dispatcher will use that convention to fetch the parameters out of the machine
				 * state, pass them into the system call defintion, and store the result back into
				 * the machine.
				 */
				// Map system call 0 to "write"
				program.getFunctionManager()
						.createFunction("write", syscall.getAddress(0),
							new AddressSet(syscall.getAddress(0)), SourceType.USER_DEFINED)
						.setCallingConvention(EmuSyscallLibrary.SYSCALL_CONVENTION_NAME);
				// Map system call 1 to "console"
				program.getFunctionManager()
						.createFunction("console", syscall.getAddress(1),
							new AddressSet(syscall.getAddress(1)), SourceType.USER_DEFINED)
						.setCallingConvention(EmuSyscallLibrary.SYSCALL_CONVENTION_NAME);
			}

			/*
			 * Create an emulator and start a thread
			 */
			PcodeEmulator emulator = new PcodeEmulator(language) {
				@Override
				protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
					return new DemoSyscallLibrary(this, program,
						StandAloneSyscallEmuExampleScript.this);
				}

				// Uncomment this to see instructions printed as they are decoded
				/*
				@Override
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

			/*
			 * The library has a reference to the program and uses it to derive types and the system
			 * call numbering. However, the emulator itself does not have access to the program. If we
			 * followed the pattern in DebuggerEmuExampleScript, the emulator would have its state bound
			 * (indirectly) to the program. We'll need to copy the bytes in. Because we created blocks
			 * that were 0x1000 bytes in size, we can be fast and loose with our buffer. Ordinarily, you
			 * may want to copy in chunks rather than taking entire memory blocks at a time.
			 */
			byte[] data = new byte[0x1000];
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!block.isInitialized()) {
					continue; // Skip the syscall/OTHER block
				}
				Address addr = block.getStart();
				block.getBytes(addr, data);
				emulator.getSharedState()
						.setVar(addr.getAddressSpace(), addr.getOffset(), data.length, true, data);
			}

			/*
			 * Initialize the thread
			 */
			PcodeProgram init =
				SleighProgramCompiler.compileProgram(language, "init", String.format("""
						RIP = 0x%s;
						RSP = 0x00001000;
						""", entry), library);
			thread.getExecutor().execute(init, library);
			thread.overrideContextWithDefault();
			thread.reInitialize();

			/*
			 * Run the experiment: This should interrupt on the second SYSCALL, because we didn't
			 * provide a system call name in OTHER space for 20.
			 */
			try {
				thread.stepInstruction(10);
				printerr("We should not have completed 10 steps!");
			}
			catch (EmuInvalidSystemCallException e) {
				println("Terminated via invalid syscall. Good.");
			}

			/*
			 * Inspect the machine. You can always do this by accessing the state directly, but for
			 * anything other than simple variables, you may find compiling an expression more
			 * convenient.
			 */
			println("RDI = " +
				Utils.bytesToLong(
					thread.getState().getVar(language.getRegister("RDI"), Reason.INSPECT), 8,
					language.isBigEndian()));

			println("RDI = " + Utils.bytesToLong(
				SleighProgramCompiler.compileExpression(language, "RDI")
						.evaluate(thread.getExecutor()),
				8, language.isBigEndian()));

			println("RDI+4 = " +
				Utils.bytesToLong(SleighProgramCompiler.compileExpression(language, "RDI+4")
						.evaluate(thread.getExecutor()),
					8, language.isBigEndian()));

		}
		finally {
			if (program != null) {
				program.release(this);
			}
		}
	}
}
