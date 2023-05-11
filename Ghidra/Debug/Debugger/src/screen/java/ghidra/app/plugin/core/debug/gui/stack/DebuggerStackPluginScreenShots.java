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
package ghidra.app.plugin.core.debug.gui.stack;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;

import org.junit.*;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.action.SPLocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.debug.stack.*;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.app.services.DebuggerEmulationService.EmulationResult;
import ghidra.async.AsyncTestUtils;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerStackPluginScreenShots extends GhidraScreenShotGenerator
		implements AsyncTestUtils {

	ProgramManager programManager;
	DebuggerTraceManagerService traceManager;
	DebuggerStaticMappingService mappingService;
	DebuggerStackPlugin stackPlugin;
	DebuggerStackProvider stackProvider;
	ToyDBTraceBuilder tb;
	Program program;

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		stackPlugin = addPlugin(tool, DebuggerStackPlugin.class);

		stackProvider = waitForComponentProvider(DebuggerStackProvider.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();

		if (program != null) {
			program.release(this);
		}
	}

	private static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private static AddressSetView set(Program program, long min, long max) {
		return new AddressSet(addr(program, min), addr(program, max));
	}

	@Test
	public void testCaptureDebuggerStackPlugin() throws Throwable {
		DomainFolder root = tool.getProject().getProjectData().getRootFolder();
		program = createDefaultProgram("echo", ToyProgramBuilder._X64, this);
		try (Transaction tx = program.openTransaction("Populate")) {
			program.setImageBase(addr(program, 0x00400000), true);
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
			FunctionManager fMan = program.getFunctionManager();
			fMan.createFunction("FUN_00401000", addr(0x00401000),
				set(program, 0x00401000, 0x00401100), SourceType.USER_DEFINED);
			fMan.createFunction("FUN_00401200", addr(0x00401200),
				set(program, 0x00401200, 0x00401300), SourceType.USER_DEFINED);
			fMan.createFunction("FUN_00404300", addr(0x00404300),
				set(program, 0x00404300, 0x00404400), SourceType.USER_DEFINED);
		}
		long snap;
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			snap = tb.trace.getTimeManager().createSnapshot("First").getKey();
			thread = tb.getOrAddThread("[1]", snap);
			TraceStack stack = tb.trace.getStackManager().getStack(thread, snap, true);
			stack.setDepth(3, true);

			TraceStackFrame frame;
			frame = stack.getFrame(0, false);
			frame.setProgramCounter(Lifespan.ALL, tb.addr(0x00404321));
			frame = stack.getFrame(1, false);
			frame.setProgramCounter(Lifespan.ALL, tb.addr(0x00401234));
			frame = stack.getFrame(2, false);
			frame.setProgramCounter(Lifespan.ALL, tb.addr(0x00401001));
		}
		root.createFile("trace", tb.trace, TaskMonitor.DUMMY);
		root.createFile("echo", program, TaskMonitor.DUMMY);
		try (Transaction tx = tb.startTransaction()) {
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(snap), tb.addr(0x00400000)),
				new ProgramLocation(program, addr(program, 0x00400000)), 0x10000, false);
		}

		programManager.openProgram(program);
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);

		captureIsolatedProvider(DebuggerStackProvider.class, 600, 300);
	}

	protected ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

	// TODO: Propose this replace waitForProgram
	public static void waitForDomainObject(DomainObject object) {
		object.flushEvents();
		waitForSwing();
	}

	protected void intoProject(DomainObject obj) {
		waitForDomainObject(obj);
		DomainFolder rootFolder = tool.getProject()
				.getProjectData()
				.getRootFolder();
		waitForCondition(() -> {
			try {
				rootFolder.createFile(obj.getName(), obj, monitor);
				return true;
			}
			catch (InvalidNameException | CancelledException e) {
				throw new AssertionError(e);
			}
			catch (IOException e) {
				// Usually "object is busy". Try again.
				return false;
			}
		});
	}

	protected void createProgram(Language lang, CompilerSpec cSpec) throws IOException {
		program = new ProgramDB("fibonacci", lang, cSpec, this);
	}

	protected void createProgram(String languageID, String cSpecID) throws IOException {
		Language language = getLanguageService().getLanguage(new LanguageID(languageID));
		CompilerSpec cSpec = cSpecID == null ? language.getDefaultCompilerSpec()
				: language.getCompilerSpecByID(new CompilerSpecID(cSpecID));
		createProgram(language, cSpec);
	}

	Address retInstr;

	protected Register register(String name) {
		return program.getLanguage().getRegister(name);
	}

	protected Function createFibonacciProgramX86_32() throws Throwable {
		createProgram("x86:LE:32:default", "gcc");
		intoProject(program);
		try (Transaction tx = program.openTransaction("Assemble")) {
			Address entry = addr(program, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
			Assembler asm =
				Assemblers.getAssembler(program.getLanguage(), StackUnwinderTest.NO_16BIT_CALLS);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

			buf.assemble("PUSH EBP");
			buf.assemble("MOV EBP, ESP");

			buf.assemble("CMP dword ptr [EBP+8], 1");
			Address jumpBase = buf.getNext();
			buf.assemble("JBE 0x" + buf.getNext());

			// Recursive case. Let EDX be sum
			// sum = fib(n - 1)
			buf.assemble("MOV ECX, dword ptr [EBP+8]");
			buf.assemble("DEC ECX");
			buf.assemble("PUSH ECX"); // pass n - 1
			buf.assemble("CALL 0x" + entry);
			buf.assemble("ADD ESP, 4"); // Clear parameters
			buf.assemble("MOV EDX, EAX");
			// sum += fib(n - 2)
			buf.assemble("MOV ECX, dword ptr [EBP+8]");
			buf.assemble("SUB ECX, 2");
			buf.assemble("PUSH EDX"); // Caller Save EDX
			buf.assemble("PUSH ECX"); // pass n - 2
			buf.assemble("CALL 0x" + entry);
			buf.assemble("ADD ESP, 4"); // Clear parameters
			buf.assemble("POP EDX"); // Restore EDX
			buf.assemble("ADD EAX, EDX");

			Address labelRet = buf.getNext();
			buf.assemble("LEAVE");
			retInstr = buf.getNext();
			buf.assemble("RET");

			Address labelBase = buf.getNext();
			buf.assemble(jumpBase, "JBE 0x" + labelBase);
			buf.assemble("MOV EAX, dword ptr [EBP+8]");
			buf.assemble("JMP 0x" + labelRet);

			byte[] bytes = buf.getBytes();
			program.getMemory().setBytes(entry, bytes);

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, null);

			Function function = program.getFunctionManager()
					.createFunction("fib", entry,
						new AddressSet(entry, entry.add(bytes.length - 1)),
						SourceType.USER_DEFINED);

			function.updateFunction("__cdecl",
				new ReturnParameterImpl(UnsignedIntegerDataType.dataType, program),
				List.of(
					new ParameterImpl("n", UnsignedIntegerDataType.dataType, program)),
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
			// NOTE: The decompiler doesn't actually use sum.... For some reason, it re-uses n
			// Still, in the tests, I can use uVar1 (EAX) as a register variable
			function.addLocalVariable(
				new LocalVariableImpl("sum", 0, UnsignedIntegerDataType.dataType, register("EDX"),
					program),
				SourceType.USER_DEFINED);
			return function;
		}
	}

	@Test
	public void testCaptureDebuggerStackUnwindInListing() throws Throwable {
		addPlugin(tool, DebuggerListingPlugin.class);

		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);
		DebuggerEmulationService emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);

		Function function = createFibonacciProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		tb.close();
		tb = new ToyDBTraceBuilder(
			ProgramEmulationUtils.launchEmulationTrace(program, entry, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		StateEditor editor = controlService.createStateEditor(tb.trace);

		DebuggerCoordinates atSetup = traceManager.getCurrent();
		StackUnwinder unwinder = new StackUnwinder(tool, atSetup.getPlatform());
		AnalysisUnwoundFrame<WatchValue> frameAtSetup = unwinder.start(atSetup, monitor);

		Parameter param1 = function.getParameter(0);
		waitOn(frameAtSetup.setValue(editor, param1, BigInteger.valueOf(9)));
		waitOn(frameAtSetup.setReturnAddress(editor, tb.addr(0xdeadbeef)));
		waitForTasks();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), retInstr,
						Set.of(),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "unwind stack");
		}

		EmulationResult result = emuService.run(atSetup.getPlatform(), atSetup.getTime(), monitor,
			Scheduler.oneThread(thread));
		Msg.debug(this, "Broke after " + result.schedule());

		traceManager.activateTime(result.schedule());
		waitForTasks();
		DebuggerCoordinates tallest = traceManager.getCurrent();
		try (Transaction tx = tb.startTransaction()) {
			new UnwindStackCommand(tool, tallest).applyTo(tb.trace, monitor);
		}
		waitForDomainObject(tb.trace);

		DebuggerListingProvider listingProvider =
			waitForComponentProvider(DebuggerListingProvider.class);
		listingProvider.setTrackingSpec(SPLocationTrackingSpec.INSTANCE);
		waitForSwing();

		captureIsolatedProvider(listingProvider, 800, 600);
	}
}
