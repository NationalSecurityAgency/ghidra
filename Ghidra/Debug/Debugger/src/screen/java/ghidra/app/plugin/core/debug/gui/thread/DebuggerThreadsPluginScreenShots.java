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
package ghidra.app.plugin.core.debug.gui.thread;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.database.time.DBTraceTimeManager;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerThreadsPluginScreenShots extends GhidraScreenShotGenerator {

	ProgramManager programManager;
	DebuggerStaticMappingServicePlugin mappingService;
	DebuggerTraceManagerService traceManager;
	DebuggerThreadsPlugin threadsPlugin;
	ToyDBTraceBuilder tb;
	Program progBash;

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		threadsPlugin = addPlugin(tool, DebuggerThreadsPlugin.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();

		if (progBash != null) {
			progBash.release(this);
		}
	}

	private static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private static AddressRange rng(Program program, long min, long max) {
		return new AddressRangeImpl(addr(program, min), addr(program, max));
	}

	private static AddressSetView set(AddressRange... ranges) {
		AddressSet set = new AddressSet();
		for (AddressRange r : ranges) {
			set.add(r);
		}
		return set;
	}

	protected boolean nullOrDead(TraceThread thread) {
		return thread == null || !thread.isAlive();
	}

	private void populateTrace() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			DBTraceObjectManager om = tb.trace.getObjectManager();
			om.createRootObject(ProgramEmulationUtils.EMU_SESSION_SCHEMA);

			DBTraceTimeManager sm = tb.trace.getTimeManager();
			sm.createSnapshot("First").getKey();
			sm.getSnapshot(13, true);

			DBTraceThreadManager tm = tb.trace.getThreadManager();
			TraceObjectThread t1 =
				(TraceObjectThread) tm.addThread("Threads[1]", "main", Lifespan.nowOn(0));
			TraceObjectThread t2 =
				(TraceObjectThread) tm.addThread("Threads[2]", "server", Lifespan.nowOn(2));
			TraceObjectThread t3 =
				(TraceObjectThread) tm.addThread("Threads[3]", "handler 1", Lifespan.span(5, 10));
			TraceObjectThread t4 =
				(TraceObjectThread) tm.addThread("Threads[4]", "handler 2", Lifespan.span(8, 13));

			t1.getObject().setValue(Lifespan.nowOn(0), "_state", "STOPPED");
			t2.getObject().setValue(Lifespan.nowOn(0), "_state", "STOPPED");
			t3.getObject().setValue(Lifespan.nowOn(0), "_state", "TERMINATED");
			t4.getObject().setValue(Lifespan.nowOn(0), "_state", "TERMINATED");

			om.createObject(TraceObjectKeyPath.parse("Threads[1].Registers"))
					.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			om.createObject(TraceObjectKeyPath.parse("Threads[2].Registers"))
					.insert(Lifespan.nowOn(2), ConflictResolution.DENY);
			om.createObject(TraceObjectKeyPath.parse("Threads[3].Registers"))
					.insert(Lifespan.nowOn(5), ConflictResolution.DENY);
			om.createObject(TraceObjectKeyPath.parse("Threads[4].Registers"))
					.insert(Lifespan.nowOn(10), ConflictResolution.DENY);
			// insert calls will extend thread life :/
			t3.getObject().getCanonicalParent(13).setMaxSnap(10);
			t4.getObject().getCanonicalParent(13).setMaxSnap(13);

			Register pc = tb.host.getLanguage().getProgramCounter();
			Register sp = tb.host.getCompilerSpec().getStackPointer();

			DBTraceMemorySpace r1 = tb.trace.getMemoryManager().getMemoryRegisterSpace(t1, true);
			r1.setValue(13, new RegisterValue(pc, BigInteger.valueOf(0x00400123)));
			r1.setValue(13, new RegisterValue(sp, BigInteger.valueOf(0x0001ff08)));

			DBTraceMemorySpace r2 = tb.trace.getMemoryManager().getMemoryRegisterSpace(t2, true);
			r2.setValue(12, new RegisterValue(pc, BigInteger.valueOf(0x004063d9)));
			r2.setValue(12, new RegisterValue(sp, BigInteger.valueOf(0x0002fe68)));

			DBTraceMemorySpace r3 = tb.trace.getMemoryManager().getMemoryRegisterSpace(t3, true);
			r3.setValue(12, new RegisterValue(pc, BigInteger.valueOf(0x004066ee)));
			r3.setValue(12, new RegisterValue(sp, BigInteger.valueOf(0x0003ff10)));

			DBTraceMemorySpace r4 = tb.trace.getMemoryManager().getMemoryRegisterSpace(t4, true);
			r4.setValue(12, new RegisterValue(pc, BigInteger.valueOf(0x004066ee)));
			r4.setValue(12, new RegisterValue(sp, BigInteger.valueOf(0x0004ff10)));
		}
	}

	private void populateTraceAndPrograms() throws Exception {
		DomainFolder root = tool.getProject().getProjectData().getRootFolder();

		populateTrace();

		progBash = createDefaultProgram("bash", ProgramBuilder._X64, this);

		try (Transaction tx = progBash.openTransaction("Add memory")) {
			progBash.setImageBase(addr(progBash, 0x00400000), true);
			progBash.getMemory()
					.createInitializedBlock(".text", addr(progBash, 0x00400000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
			progBash.getMemory()
					.createInitializedBlock(".data", addr(progBash, 0x00600000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);

			progBash.getFunctionManager()
					.createFunction("main", addr(progBash, 0x00400000),
						set(rng(progBash, 0x00400000, 0x00400fff)), SourceType.ANALYSIS);
			progBash.getFunctionManager()
					.createFunction("service_loop", addr(progBash, 0x00406000),
						set(rng(progBash, 0x00406000, 0x004063ff)), SourceType.ANALYSIS);
			progBash.getFunctionManager()
					.createFunction("parse_req", addr(progBash, 0x00406600),
						set(rng(progBash, 0x00406600, 0x004066ff)), SourceType.ANALYSIS);
		}

		root.createFile("trace", tb.trace, TaskMonitor.DUMMY);
		root.createFile("bash", progBash, TaskMonitor.DUMMY);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		programManager.openProgram(progBash);
		waitForTasks();

		mappingService.addMapping(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000)),
			new ProgramLocation(progBash, addr(progBash, 0x00400000)), 0x10000, true);
		mappingService.changesSettled().get(1, TimeUnit.SECONDS);
	}

	@Test
	public void testCaptureDebuggerThreadsPlugin() throws Throwable {
		populateTraceAndPrograms();
		traceManager.activateSnap(12);
		waitForTasks();
		traceManager.activateSnap(13);
		waitForTasks();

		captureIsolatedProvider(DebuggerThreadsProvider.class, 900, 300);
	}
}
