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
package ghidra.app.plugin.core.debug.gui.time;

import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerTimePluginScreenShots extends GhidraScreenShotGenerator {

	private static final TaskMonitor MONITOR = new ConsoleTaskMonitor();

	ProgramManager programManager;
	DebuggerTraceManagerService traceManager;
	DebuggerStaticMappingService mappingService;

	DebuggerTimePlugin timePlugin;
	DebuggerTimeProvider timeProvider;

	ToyDBTraceBuilder tb;
	Program progHw;
	Program progLibc;

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

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		timePlugin = addPlugin(tool, DebuggerTimePlugin.class);
		timeProvider = waitForComponentProvider(DebuggerTimeProvider.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
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
	public void testCaptureDebuggerTimePlugin() throws Throwable {
		progHw = createDefaultProgram("helloworld", ToyProgramBuilder._X64, this);
		progLibc = createDefaultProgram("libc", ToyProgramBuilder._X64, this);

		long fakeClock = (long) Integer.MAX_VALUE * 1000;
		TraceSnapshot snap;

		try (Transaction tx = progHw.openTransaction("Populate main")) {
			progHw.getMemory()
					.createInitializedBlock(".text", tb.addr(0x00400000), 0x2000, (byte) 0, MONITOR,
						false);
			progHw.getFunctionManager()
					.createFunction("main", tb.addr(0x00401234),
						tb.set(tb.range(0x00401234, 0x00401300)), SourceType.IMPORTED);
		}
		try (Transaction tx = progLibc.openTransaction("Populate puts")) {
			progLibc.getMemory()
					.createInitializedBlock(".text", tb.addr(0x00400000), 0x2000, (byte) 0, MONITOR,
						false);
			progLibc.getFunctionManager()
					.createFunction("puts", tb.addr(0x00400110),
						tb.set(tb.range(0x00400110, 0x00400120)), SourceType.IMPORTED);
		}

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
						tb.range(0x00400000, 0x00402000), 0);
			tb.trace.getModuleManager()
					.addLoadedModule("Modules[libc]", "libc",
						tb.range(0x7fff0000, 0x7fff2000), 0);

			mappingService.addMapping(
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000)),
				new ProgramLocation(progHw, tb.addr(0x00400000)), 0x2000, false);
			mappingService.addMapping(
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x7fff0000)),
				new ProgramLocation(progLibc, tb.addr(0x00400000)), 0x2000, false);

			TraceThread thread = tb.getOrAddThread("Threads[1]", 0);
			tb.trace.getObjectManager()
					.createObject(KeyPath.parse("Threads[1].Registers"))
					.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			thread.setName(0, "1 main");
			TraceMemorySpace regs =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			Register pc = tb.host.getLanguage().getProgramCounter();

			snap = tb.trace.getTimeManager().createSnapshot("STOP");
			snap.setEventThread(thread);
			snap.setRealTime(fakeClock);
			fakeClock += 1000;
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x00401234)));

			snap = tb.trace.getTimeManager().createSnapshot("BREAK");
			snap.setEventThread(thread);
			snap.setRealTime(fakeClock);
			fakeClock += 2300;
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x7fff0110)));

			snap = tb.trace.getTimeManager().createSnapshot("STEP");
			snap.setEventThread(thread);
			snap.setRealTime(fakeClock);
			snap.setSchedule(TraceSchedule.parse(snap.getKey() - 1 + ":1"));
			fakeClock += 444;
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x7fff0113)));

			snap = tb.trace.getTimeManager().createSnapshot("STEP");
			snap.setEventThread(thread);
			snap.setRealTime(fakeClock);
			snap.setSchedule(TraceSchedule.parse(snap.getKey() - 1 + ":1"));
			fakeClock += 100;
			regs.setValue(snap.getKey(), new RegisterValue(pc, BigInteger.valueOf(0x7fff0115)));
		}

		mappingService.changesSettled().get(1, TimeUnit.SECONDS);

		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(snap.getKey());

		captureIsolatedProvider(timeProvider, 600, 400);
	}
}
