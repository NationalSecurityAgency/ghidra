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
package ghidra.app.plugin.core.debug.gui.variable;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import db.Transaction;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueHoverPlugin;
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
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
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
public class DebuggerVariableViewerPluginScreenShots extends GhidraScreenShotGenerator
		implements AsyncTestUtils {

	private static final TaskMonitor MONITOR = new ConsoleTaskMonitor();
	ToyDBTraceBuilder tb;
	Program progHw;
	private ProgramManagerPlugin programManager;
	private DebuggerTraceManagerServicePlugin traceManager;
	private DebuggerVariableViewerProvider provider;
	private DebuggerStaticMappingServicePlugin mappingService;
	private ProgressService progressService;

	@Before
	public void setUpMine() throws Exception {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		progressService = addPlugin(tool, ProgressServicePlugin.class);

		addPlugin(tool, DebuggerVariableViewerPlugin.class);

		// The unwinder has a dependency on this plugin so it's required
		addPlugin(tool, VariableValueHoverPlugin.class);

		provider = waitForComponentProvider(DebuggerVariableViewerProvider.class);

		populateTraceAndPrograms();
	}

	private void populateTraceAndPrograms() throws Exception {
		ToyProgramBuilder helloworldBuilder = new ToyProgramBuilder("helloworld", false, this);
		helloworldBuilder.tx(() -> {
			helloworldBuilder.createMemory(".text", "0x00400000", 0x50);
			Function function =
					helloworldBuilder.createEmptyFunction("main", null, "__fastcall", false,
							"0x00400000", 6, IntegerDataType.dataType,
							new ParameterImpl("argc", IntegerDataType.dataType,
									helloworldBuilder.getProgram()),
							new ParameterImpl("argv", new PointerDataType(CharDataType.dataType),
									helloworldBuilder.getProgram()),
							new ParameterImpl("float_arg", FloatDataType.dataType,
									helloworldBuilder.getProgram()));

			progHw = helloworldBuilder.getProgram();

			helloworldBuilder.createReturnInstruction("0x00400000");

			function.addLocalVariable(
					new LocalVariableImpl("StackVar", IntegerDataType.dataType, 4, progHw),
					SourceType.USER_DEFINED);
		});

		tb = new ToyDBTraceBuilder("toy", progHw.getLanguage().getLanguageID().getIdAsString());

		intoProject(progHw);
		intoProject(tb.trace);
		programManager.openProgram(progHw);

		traceManager.openTrace(tb.trace);
		mappingService.changesSettled().get(1, TimeUnit.SECONDS);

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ProgramEmulationUtils.EMU_SESSION_SCHEMA);

			tb.trace.getModuleManager()
					.addLoadedModule("Modules[helloword]", "helloworld",
							tb.range(0x00400000, 0x00400050), 0);

			tb.trace.getMemoryManager()
					.addRegion("Memory[ALL]", Lifespan.nowOn(0),
							tb.range(0x0, 0xFFFF_FFFF_FFFF_FFFFL), TraceMemoryFlag.READ,
							TraceMemoryFlag.EXECUTE, TraceMemoryFlag.WRITE);

			mappingService.addIdentityMapping(tb.trace, progHw, Lifespan.nowOn(0), true);

			TraceThread thread = tb.getOrAddThread("Threads[1]", 0);
			tb.createObjectsRegsForThread(thread, Lifespan.nowOn(0), tb.host);
			TraceMemorySpace regs =
					tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			Register arg1 = tb.trace.getBaseLanguage().getRegister("r12");
			Register arg2 = tb.trace.getBaseLanguage().getRegister("r11");
			Register arg3 = tb.trace.getBaseLanguage().getRegister("r10");
			Register sp = tb.trace.getBaseLanguage().getRegister("sp");

			TraceSnapshot snap = tb.trace.getTimeManager().createSnapshot("Start main");
			snap.setEventThread(thread);

			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00400000)));
			regs.setValue(snap.getKey(), new RegisterValue(arg1, BigInteger.valueOf(0x3)));
			regs.setValue(snap.getKey(), new RegisterValue(arg2, BigInteger.valueOf(0xdeadbeefL)));
			regs.setValue(snap.getKey(),
					new RegisterValue(arg3, BigInteger.valueOf(Float.floatToIntBits(1.5f))));
			regs.setValue(snap.getKey(), new RegisterValue(sp, BigInteger.valueOf(0x00200000)));

			tb.trace.getStackManager()
					.getStack(thread, snap.getKey(), true)
					.getFrame(snap.getKey(), 0, true)
					.setProgramCounter(Lifespan.at(snap.getKey()), tb.addr(0x00400000));

			tb.trace.getMemoryManager()
					.putBytes(snap.getKey(), tb.addr(0x00200004),
							ByteBuffer.wrap(new byte[] { 0x21, 0x43, 0x65, (byte) 0x87 }));
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
	}

	@Test
	public void testCaptureDebuggerVariableViewerPlugin() throws InterruptedException {
		for (MonitorReceiver e : progressService.getAllMonitors()) {
			waitFor(() -> !e.isValid());
		}
		JTable table = findComponent(provider.getComponent(), JTable.class);
		Thread.sleep(2000);
		waitFor(() -> table.getRowCount() > 0);
		captureIsolatedProvider(provider, 500, 500);
	}

	@Test
	public void testCaptureDebuggerVariableViewerPluginRightClick() throws InterruptedException {
		for (MonitorReceiver e : progressService.getAllMonitors()) {
			waitFor(() -> !e.isValid());
		}
		runSwing(() -> {
			Window window = tool.getWindowManager().getProviderWindow(provider);
			if (window == null) {
				throw new AssertException(
						"Could not find window for " + "provider--is it showing?: " +
						provider.getName());
			}

			window.setSize(new Dimension(500, 500));
			window.toFront();
			provider.getComponent().requestFocus();
			paintFix(window);
		});

		waitForSwing();
		JTable table = findComponent(provider.getComponent(), JTable.class);
		Thread.sleep(2000);
		waitFor(() -> table.getRowCount() > 0);
		selectRow(table, 0);
		Rectangle cellRect = table.getCellRect(0, 0, true);
		rightClick(table, cellRect.x + cellRect.width / 2, cellRect.y + cellRect.height / 2);
		JPopupMenu popupMenu = getPopupMenu();
		MenuElement menuElement =
				Arrays.stream(popupMenu.getSubElements()).findFirst().orElseThrow();
		postEvent(new MouseEvent(menuElement.getComponent(), MouseEvent.MOUSE_ENTERED,
				System.currentTimeMillis(), 0, menuElement.getComponent().getWidth(), 0, 0,
				false));
		captureProviderWithScreenShot(provider);
	}
}
