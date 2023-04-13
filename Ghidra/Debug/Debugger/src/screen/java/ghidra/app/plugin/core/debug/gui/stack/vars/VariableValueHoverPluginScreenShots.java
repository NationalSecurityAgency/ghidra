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
package ghidra.app.plugin.core.debug.gui.stack.vars;

import java.awt.Rectangle;
import java.awt.Window;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import org.junit.Test;

import db.Transaction;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.Unique;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.debug.stack.*;
import ghidra.app.plugin.core.debug.stack.StackUnwinderTest.HoverLocation;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.app.services.DebuggerEmulationService.EmulationResult;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class VariableValueHoverPluginScreenShots extends GhidraScreenShotGenerator
		implements AsyncTestUtils {

	ProgramManager programManager;
	DebuggerTraceManagerService traceManager;
	DebuggerStaticMappingService mappingService;
	ToyDBTraceBuilder tb;
	Program program;

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

	Map<Address, Integer> stackRefInstrs = new HashMap<>();
	Address registerRefInstr;
	Address retInstr;

	protected Register register(String name) {
		return program.getLanguage().getRegister(name);
	}

	private static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
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

			stackRefInstrs.put(buf.getNext(), 0);
			buf.assemble("CMP dword ptr [EBP+8], 1");
			Address jumpBase = buf.getNext();
			buf.assemble("JBE 0x" + buf.getNext());

			// Recursive case. Let EDX be sum
			// sum = fib(n - 1)
			stackRefInstrs.put(buf.getNext(), 1);
			buf.assemble("MOV ECX, dword ptr [EBP+8]");
			buf.assemble("DEC ECX");
			buf.assemble("PUSH ECX"); // pass n - 1
			buf.assemble("CALL 0x" + entry);
			buf.assemble("ADD ESP, 4"); // Clear parameters
			registerRefInstr = buf.getNext();
			buf.assemble("MOV EDX, EAX");
			// sum += fib(n - 2)
			stackRefInstrs.put(buf.getNext(), 1);
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
			stackRefInstrs.put(buf.getNext(), 1);
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

			AddressSpace stack = program.getAddressFactory().getStackSpace();
			for (Map.Entry<Address, Integer> ent : stackRefInstrs.entrySet()) {
				Instruction ins = program.getListing().getInstructionAt(ent.getKey());
				ins.addOperandReference(ent.getValue(), stack.getAddress(4), RefType.READ,
					SourceType.ANALYSIS);
			}
			return function;
		}
	}

	protected void prepareContext() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		programManager.closeAllPrograms(true);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		addPlugin(tool, DebuggerListingPlugin.class);
		addPlugin(tool, VariableValueHoverPlugin.class);

		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);
		DebuggerEmulationService emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);

		Function function = createFibonacciProgramX86_32();
		GhidraProgramUtilities.markProgramAnalyzed(program);
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		tb = new ToyDBTraceBuilder(
			ProgramEmulationUtils.launchEmulationTrace(program, entry, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		try (Transaction tx = tb.startTransaction()) {
			MemoryBlock block = program.getMemory().getBlock(".text");
			byte[] text = new byte[(int) block.getSize()];
			block.getBytes(block.getStart(), text);

			tb.trace.getMemoryManager().putBytes(0, block.getStart(), ByteBuffer.wrap(text));

			Disassembler dis =
				Disassembler.getDisassembler(tb.trace.getProgramView(), monitor, null);
			dis.disassemble(entry, null);
		}
		waitForDomainObject(tb.trace);

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
	}

	@Test
	public void testCaptureVariableValueHoverPluginListing() throws Throwable {
		prepareContext();

		// We're cheating the address game, but both use the same language without relocation
		Instruction ins = tb.trace.getCodeManager().instructions().getAt(0, registerRefInstr);

		DebuggerListingProvider listingProvider =
			waitForComponentProvider(DebuggerListingProvider.class);
		ListingPanel listingPanel = listingProvider.getListingPanel();

		Window window = moveProviderToItsOwnWindow(listingProvider, 900, 600);
		window.toFront();
		waitForSwing();

		HoverLocation loc =
			StackUnwinderTest.findOperandLocation(listingPanel, ins, register("EDX"));
		FieldLocation fLoc = loc.fLoc();
		BigInteger refIndex = listingPanel.getAddressIndexMap().getIndex(registerRefInstr);

		FieldPanel fieldPanel = listingPanel.getFieldPanel();
		runSwing(() -> fieldPanel.goTo(refIndex, fLoc.fieldNum, fLoc.row, fLoc.col, false));
		waitForSwing();

		Rectangle rect = listingPanel.getCursorBounds();

		MouseEvent event =
			new MouseEvent(fieldPanel, 0, System.currentTimeMillis(), 0, rect.x, rect.y, 0, false);
		fieldPanel.getHoverHandler().mouseHovered(event);
		waitForSwing();

		captureProviderWithScreenShot(listingProvider);
	}

	@Test
	public void testCaptureVariableValueHoverPluginBrowser() throws Throwable {
		CodeViewerProvider browserProvider = waitForComponentProvider(CodeViewerProvider.class);
		prepareContext();

		List<Address> stackRefs = new ArrayList<>(stackRefInstrs.keySet());
		Address refAddr = stackRefs.get(2);
		Instruction ins = program.getListing().getInstructionAt(refAddr);

		ListingPanel listingPanel = browserProvider.getListingPanel();

		Window window = moveProviderToItsOwnWindow(browserProvider, 1000, 600);
		window.toFront();
		waitForSwing();

		HoverLocation loc =
			StackUnwinderTest.findOperandLocation(listingPanel, ins, new Scalar(32, 8));
		FieldLocation fLoc = loc.fLoc();
		BigInteger refIndex = listingPanel.getAddressIndexMap().getIndex(refAddr);

		FieldPanel fieldPanel = listingPanel.getFieldPanel();
		runSwing(() -> fieldPanel.goTo(refIndex, fLoc.fieldNum, fLoc.row, fLoc.col, false));
		waitForSwing();

		Rectangle rect = listingPanel.getCursorBounds();

		MouseEvent event =
			new MouseEvent(fieldPanel, 0, System.currentTimeMillis(), 0, rect.x, rect.y, 0, false);
		fieldPanel.getHoverHandler().mouseHovered(event);
		waitForSwing();

		captureProviderWithScreenShot(browserProvider);
	}

	@Test
	public void testCaptureVariableValueHoverPluginDecompiler() throws Throwable {
		DecompilerProvider decompilerProvider = waitForComponentProvider(DecompilerProvider.class);
		tool.showComponentProvider(decompilerProvider, true);
		prepareContext();

		Function function = program.getFunctionManager().getFunctionContaining(registerRefInstr);

		DecompilerPanel decompilerPanel = decompilerProvider.getDecompilerPanel();

		Window window = moveProviderToItsOwnWindow(decompilerProvider, 600, 600);
		window.toFront();
		waitForSwing();

		HoverLocation loc =
			StackUnwinderTest.findTokenLocation(decompilerPanel, function, "n", "if (1 < n) {");
		runSwing(() -> decompilerPanel.goToToken(loc.token()));
		waitForSwing();

		FieldPanel fieldPanel = decompilerPanel.getFieldPanel();
		Rectangle rect = fieldPanel.getCursorBounds();

		MouseEvent event =
			new MouseEvent(fieldPanel, 0, System.currentTimeMillis(), 0, rect.x, rect.y, 0, false);
		fieldPanel.getHoverHandler().mouseHovered(event);
		waitForSwing();

		captureProviderWithScreenShot(decompilerProvider);
	}
}
