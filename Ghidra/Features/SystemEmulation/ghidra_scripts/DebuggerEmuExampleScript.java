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
//An example emulation script that integrates well with the Debgger UI.
//It provides the set-up code and then demonstrates some use cases.
//It should work with any x64 program, but some snippets may require specific conditions.
//It should be easily ported to other platforms just by adjusting register names.
//@author 
//@category Emulation
//@keybinding
//@menupath
//@toolbar

import java.nio.charset.Charset;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.service.emulation.BytesDebuggerPcodeEmulator;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.emulation.data.DefaultPcodeDebuggerAccess;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.pcode.utils.Utils;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;

public class DebuggerEmuExampleScript extends GhidraScript {
	private final static Charset UTF8 = Charset.forName("utf8");

	@Override
	protected void run() throws Exception {
		/*
		 * First, get all the services and stuff:
		 */
		PluginTool tool = state.getTool();
		ProgramManager programManager = tool.getService(ProgramManager.class);
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		SleighLanguage language = (SleighLanguage) getLanguage(new LanguageID("x86:LE:64:default"));

		/*
		 * I'll generate a new program, because I don't want to require the user to pick something
		 * specific.
		 */
		Address entry;
		Address injectHere;
		Program program = null;
		try {
			program =
				new ProgramDB("emu_example", language, language.getDefaultCompilerSpec(), this);
			// Save the program into the project so it has a URL for the trace's static mapping
			tool.getProject()
					.getProjectData()
					.getRootFolder()
					.createFile("emu_example", program, monitor);
			try (Transaction tx = program.openTransaction("Init")) {
				AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
				entry = space.getAddress(0x00400000);
				Address dataEntry = space.getAddress(0x00600000);
				Memory memory = program.getMemory();
				memory.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
				Assembler asm = Assemblers.getAssembler(program);
				InstructionIterator ii = asm.assemble(entry,
					"MOV RCX, 0x" + dataEntry,
					"MOV RAX, 1",
					"SYSCALL",
					"MOV RAX, 2",
					"SYSCALL");
				ii.next(); // drop MOV RCX
				injectHere = ii.next().getAddress();
				memory.createInitializedBlock(".data", dataEntry, 0x1000, (byte) 0, monitor, false);
				memory.setBytes(dataEntry, "Hello, World!\n".getBytes(UTF8));
			}
			program.save("Init", monitor);
			// Display the program in the UI
			programManager.openProgram(program);
		}
		finally {
			if (program != null) {
				program.release(this);
			}
		}

		/*
		 * Now, load the program into a trace. This doesn't copy any bytes, it just sets up a static
		 * mapping. The emulator will know how to read through to the mapped program. We use a
		 * utility, which is the same used by the "Emulate Program" action in the UI. It will load
		 * the program, allocate a stack, and initialize the first thread to the given entry.
		 */
		Trace trace = null;
		try {
			trace = ProgramEmulationUtils.launchEmulationTrace(program, entry, this);
			// Display the trace in the UI
			traceManager.openTrace(trace);
			traceManager.activateTrace(trace);
		}
		finally {
			if (trace != null) {
				trace.release(this);
			}
		}
		// Get the initial thread
		TraceThread traceThread = trace.getThreadManager().getAllThreads().iterator().next();
		traceManager.activateThread(traceThread);

		/*
		 * Instead of using the UI's emulator, this script will create its own with a custom
		 * library. This emulator will still know how to integrate with the UI, reading through to
		 * open programs and writing state back into the trace.
		 */
		TracePlatform host = trace.getPlatformManager().getHostPlatform();
		DefaultPcodeDebuggerAccess access = new DefaultPcodeDebuggerAccess(tool, null, host, 0);
		BytesDebuggerPcodeEmulator emulator = new BytesDebuggerPcodeEmulator(access) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return new DemoPcodeUseropLibrary(language, DebuggerEmuExampleScript.this);
			}
		};
		// Conventionally, emulator threads are named after their trace thread's path.
		PcodeThread<byte[]> thread = emulator.getThread(traceThread.getPath(), true);

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
		 * 
		 * For demonstration, we'll record a trace snapshot for every step of emulation. This is not
		 * ordinarily recommended except for very small experiments. A more reasonable approach in
		 * practice may be to snapshot on specific breakpoints.
		 */
		TraceTimeManager time = trace.getTimeManager();
		TraceSnapshot snapshot = time.getSnapshot(0, true);
		try (Transaction tx = trace.openTransaction("Emulate")) {
			for (int i = 0; i < 10; i++) {
				println("Executing: " + thread.getCounter());
				thread.stepInstruction();
				snapshot =
					time.createSnapshot("Stepped to " + thread.getCounter());
				emulator.writeDown(host, snapshot.getKey(), 0);
			}
			printerr("We should not have completed 10 steps!");
		}
		catch (InterruptPcodeExecutionException e) {
			println("Terminated via interrupt. Good.");
		}
		// Display the final snapshot in the UI
		traceManager.activateSnap(snapshot.getKey());

		/*
		 * Inspect the machine. You can always do this by accessing the state directly, but for
		 * anything other than simple variables, you may find compiling an expression more
		 * convenient.
		 * 
		 * This works the same as in the stand-alone case.
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

		/*
		 * To evaluate a Sleigh expression against the trace: The result is the same as evaluating
		 * directly against the emulator, but these work with any trace, no matter the original data
		 * source (live target, emulated, imported, etc.) It's also built into utilities, making it
		 * easier to use.
		 */
		println("RCX+4 (trace) = " +
			TraceSleighUtils.evaluate("RCX+4", trace, snapshot.getKey(), traceThread, 0));
	}
}
