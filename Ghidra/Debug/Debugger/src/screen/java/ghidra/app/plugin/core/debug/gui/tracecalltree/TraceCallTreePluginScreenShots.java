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
package ghidra.app.plugin.core.debug.gui.tracecalltree;

import java.awt.*;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import db.Transaction;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.progress.ProgressServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.ProgressService;
import ghidra.async.AsyncTestUtils;
import ghidra.debug.api.progress.MonitorReceiver;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;
import org.junit.*;
import org.junit.experimental.categories.Category;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class TraceCallTreePluginScreenShots extends GhidraScreenShotGenerator
		implements AsyncTestUtils {

	private static final TaskMonitor MONITOR = new ConsoleTaskMonitor();
	ToyDBTraceBuilder tb;
	Program progHw;
	Program progLibc;
	private ProgramManagerPlugin programManager;
	private DebuggerTraceManagerServicePlugin traceManager;
	private TraceCallTreeProvider provider;
	private DebuggerStaticMappingServicePlugin mappingService;
	private ProgressService progressService;

	@Before
	public void setUpMine() throws Exception {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		progressService = addPlugin(tool, ProgressServicePlugin.class);

		addPlugin(tool, TraceCallTreePlugin.class);

		provider = waitForComponentProvider(TraceCallTreeProvider.class);

		populateTraceAndPrograms();
	}

	private void populateTraceAndPrograms() throws Exception {
		ToyProgramBuilder helloworldBuilder = new ToyProgramBuilder("helloworld", false, this);
		helloworldBuilder.createMemory(".text", "0x00400000", 0x50);
		helloworldBuilder.createEmptyFunction("main", null, "__fastcall", false, "0x00400000", 6,
				IntegerDataType.dataType,
				new ParameterImpl("argc", IntegerDataType.dataType,
						helloworldBuilder.getProgram()),
				new ParameterImpl("argv", CharDataType.dataType, helloworldBuilder.getProgram()));
		helloworldBuilder.createEmptyFunction("print", null, "__fastcall", false, "0x00400006", 2,
				VoidDataType.dataType,
				new ParameterImpl("string", CharDataType.dataType,
						helloworldBuilder.getProgram()));
		helloworldBuilder.createCallInstruction("0x00400000", "0x00400006");
		helloworldBuilder.createCallInstruction("0x00400002", "0x00400050");
		helloworldBuilder.createReturnInstruction("0x00400004");
		helloworldBuilder.createJmpInstruction("0x00400006", "0x00400054");
		progHw = helloworldBuilder.getProgram();

		ToyProgramBuilder libcBuilder = new ToyProgramBuilder("libc", false, this);
		libcBuilder.createMemory(".text", "0x00400050", 0x50);
		libcBuilder.createEmptyFunction("gets", null, "__fastcall", false, "0x00400050", 3,
				CharDataType.dataType);
		libcBuilder.createEmptyFunction("printf", null, "__fastcall", false, "0x00400054", 3,
				VoidDataType.dataType,
				new ParameterImpl("string", CharDataType.dataType,
						helloworldBuilder.getProgram()));
		libcBuilder.createNOPInstruction("0x00400050", 1);
		libcBuilder.createReturnInstruction("0x00400052");
		libcBuilder.createNOPInstruction("0x00400054", 1);
		libcBuilder.createReturnInstruction("0x00400056");
		progLibc = libcBuilder.getProgram();

		tb = new ToyDBTraceBuilder("toy",
				libcBuilder.getLanguage().getLanguageID().getIdAsString());

		intoProject(progHw);
		intoProject(progLibc);
		intoProject(tb.trace);
		programManager.openProgram(progLibc);
		programManager.openProgram(progHw);

		traceManager.openTrace(tb.trace);
		mappingService.changesSettled().get(1, TimeUnit.SECONDS);

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ProgramEmulationUtils.EMU_SESSION_SCHEMA);

			tb.trace.getModuleManager()
					.addLoadedModule("Modules[helloword]", "helloworld",
							tb.range(0x00400000, 0x00400050), 0);
			tb.trace.getModuleManager()
					.addLoadedModule("Modules[libc]", "libc", tb.range(0x00400050, 0x00400100), 0);

			tb.trace.getMemoryManager()
					.addRegion("Memory[ALL]", Lifespan.nowOn(0),
							tb.range(0x0, 0xFFFF_FFFF_FFFF_FFFFL), TraceMemoryFlag.READ,
							TraceMemoryFlag.EXECUTE, TraceMemoryFlag.WRITE);

			mappingService.addIdentityMapping(tb.trace, progHw, Lifespan.nowOn(0), true);
			mappingService.addIdentityMapping(tb.trace, progLibc, Lifespan.nowOn(0), true);

			TraceThread thread = tb.getOrAddThread("Threads[1]", 0);
			tb.createObjectsRegsForThread(thread, Lifespan.nowOn(0), tb.host);
			TraceMemorySpace regs =
					tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			Register arg1 = tb.trace.getBaseLanguage().getRegister("r12");
			Register arg2 = tb.trace.getBaseLanguage().getRegister("r11");

			TraceSnapshot snap = tb.trace.getTimeManager().createSnapshot("Start main");
			snap.setEventThread(thread);
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00400000)));
			regs.setValue(snap.getKey(), new RegisterValue(arg1, BigInteger.valueOf(0x3)));
			regs.setValue(snap.getKey(), new RegisterValue(arg2, BigInteger.valueOf(0x1337)));

			snap = tb.trace.getTimeManager().createSnapshot("in print");
			snap.setEventThread(thread);
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00400006)));
			regs.setValue(snap.getKey(), new RegisterValue(arg1, BigInteger.valueOf(0x345807)));

			snap = tb.trace.getTimeManager().createSnapshot("in printf");
			snap.setEventThread(thread);
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00400054)));
			regs.setValue(snap.getKey(), new RegisterValue(arg1, BigInteger.valueOf(0x345807)));

			snap = tb.trace.getTimeManager().createSnapshot("return printf");
			snap.setEventThread(thread);
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00400056)));

			snap = tb.trace.getTimeManager().createSnapshot("in main");
			snap.setEventThread(thread);
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00400002)));

			snap = tb.trace.getTimeManager().createSnapshot("in gets");
			snap.setEventThread(thread);
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00400050)));

			snap = tb.trace.getTimeManager().createSnapshot("return gets");
			snap.setEventThread(thread);
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00400052)));
			regs.setValue(snap.getKey(), new RegisterValue(arg1, BigInteger.valueOf(0x1234)));

			snap = tb.trace.getTimeManager().createSnapshot("return main");
			snap.setEventThread(thread);
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00400004)));
			regs.setValue(snap.getKey(), new RegisterValue(arg1, BigInteger.valueOf(-0x1)));

		}

		mappingService.changesSettled().get(1, TimeUnit.SECONDS);

		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(0);
	}

	protected void intoProject(DomainObject obj) {
		waitForDomainObject(obj);
		DomainFolder rootFolder = tool.getProject().getProjectData().getRootFolder();
		waitForCondition(() -> {
			try {
				rootFolder.createFile(obj.getName(), obj, MONITOR);
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

	public static void waitForDomainObject(DomainObject object) {
		object.flushEvents();
		waitForSwing();
	}

	@After
	public void tearDownMine() {
		tb.close();

		if (progHw != null) {
			progHw.release(this);
			progHw = null;
		}
		if (progLibc != null) {
			progLibc.release(this);
			progLibc = null;
		}
	}

	@Test
	public void testCaptureTraceCallTreePluginUnfolded() {
		selectRow(provider.treeTable.getTable(), 0);
		performAction(provider.unfoldRecursiveAction, true);
		for (MonitorReceiver e : progressService.getAllMonitors()) {
			waitFor(() -> !e.isValid());
		}
		captureIsolatedProvider(provider, 750, 500);
	}

	@Test
	public void testCaptureTraceCallTreePlugin() {
		captureIsolatedProvider(provider, 750, 500);
	}

	@Test
	public void testCaptureTraceCallTreePluginRightClick() {
		selectRow(provider.treeTable.getTable(), 0);
		Rectangle cellRect = provider.treeTable.getTable().getCellRect(0, 0, true);
		rightClick(provider.treeTable.getTable(), cellRect.x + cellRect.width / 2,
				cellRect.y + cellRect.height / 2);
		runSwing(() -> {
			Window window = tool.getWindowManager().getProviderWindow(provider);
			if (window == null) {
				throw new AssertException(
						"Could not find window for " + "provider--is it showing?: " +
						provider.getName());
			}

			window.setSize(new Dimension(750, 500));
			window.toFront();
			provider.getComponent().requestFocus();
			paintFix(window);
		});

		waitForSwing();
		captureProviderWithScreenShot(provider);
	}

	@Test
	public void testCaptureTraceCallTreePluginHideReturns() {
		selectRow(provider.treeTable.getTable(), 0);
		performAction(provider.unfoldRecursiveAction, true);
		performAction(provider.showReturnsToggleAction, true);
		for (MonitorReceiver e : progressService.getAllMonitors()) {
			waitFor(() -> !e.isValid());
		}
		captureIsolatedProvider(provider, 750, 500);
	}
}
