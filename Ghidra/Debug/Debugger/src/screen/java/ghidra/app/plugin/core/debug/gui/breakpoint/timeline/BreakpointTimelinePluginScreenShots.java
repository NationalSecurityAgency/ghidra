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
package ghidra.app.plugin.core.debug.gui.breakpoint.timeline;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import db.Transaction;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.async.AsyncTestUtils;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.breakpoint.DBTraceBreakpointManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;
import org.junit.*;
import org.junit.experimental.categories.Category;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class BreakpointTimelinePluginScreenShots extends GhidraScreenShotGenerator
		implements AsyncTestUtils {

	private static final TaskMonitor MONITOR = new ConsoleTaskMonitor();
	ToyDBTraceBuilder tb;
	Program progHw;
	Program progLibc;
	private ProgramManagerPlugin programManager;
	private DebuggerTraceManagerServicePlugin traceManager;
	private BreakpointTimelineProvider provider;
	private DebuggerStaticMappingServicePlugin mappingService;

	@Before
	public void setUpMine() throws Exception {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);

		addPlugin(tool, BreakpointTimelinePlugin.class);

		tb = new ToyDBTraceBuilder("toy", ToyProgramBuilder._X64);
		provider = waitForComponentProvider(BreakpointTimelineProvider.class);

		populateTraceAndPrograms();
	}

	private void populateTraceAndPrograms() throws Exception {
		ToyProgramBuilder helloworld_builder = new ToyProgramBuilder("helloworld", false, this);
		helloworld_builder.createMemory(".text", "0x00400000", 0x2000);
		helloworld_builder.createLabel("0x00401234", "main");
		helloworld_builder.createFunction("0x00401234");
		progHw = helloworld_builder.getProgram();

		ToyProgramBuilder libc_builder = new ToyProgramBuilder("libc", false, this);
		libc_builder.createMemory(".text", "0x7fff0000", 0x2000);
		libc_builder.createLabel("0x7fff0110", "puts");
		libc_builder.createFunction("0x7fff0110");
		progLibc = libc_builder.getProgram();

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
					.addLoadedModule("Modules[libc]", "libc", tb.range(0x7fff0000, 0x7fff2000), 0);

			mappingService.addIdentityMapping(tb.trace, progHw, Lifespan.nowOn(0), true);
			mappingService.addIdentityMapping(tb.trace, progLibc, Lifespan.nowOn(0), true);

			TraceThread thread = tb.getOrAddThread("Threads[1]", 0);
			tb.trace.getObjectManager()
					.createObject(KeyPath.parse("Threads[1].Registers"))
					.insert(Lifespan.nowOn(0), TraceObject.ConflictResolution.DENY);
			thread.setName(0, "1 main");

			List<Address> pcs =
					Arrays.asList(tb.addr(0x00401234), tb.addr(0x7fff0110), tb.addr(0x7fff0113),
							tb.addr(0x7fff0115));
			List<Address> memRefs =
					Arrays.asList(tb.addr(0x11111), tb.addr(0x22222), tb.addr(0x33333), null, null,
							null, null);
			List<RefType> refTypes = List.of(RefType.READ, RefType.WRITE);
			Random rand = new Random(1337);

			for (int i = 0; i < 200; i++) {
				addSnap(thread, pcs.get(rand.nextInt(pcs.size())), i,
						memRefs.get(rand.nextInt(memRefs.size())),
						refTypes.get(rand.nextInt(refTypes.size())));

			}

			DBTraceBreakpointManager bm = tb.trace.getBreakpointManager();
			bm.placeBreakpoint("Breakpoints[1]", 0, tb.addr(0x00401234), List.of(),
					TraceBreakpointKind.CommonSet.SWX.kinds(), true, "");
			bm.placeBreakpoint("Breakpoints[2]", 0, tb.addr(0x11111), List.of(),
					TraceBreakpointKind.CommonSet.READ.kinds(), true, "");
			bm.placeBreakpoint("Breakpoints[3]", 0, tb.addr(0x22222), List.of(),
					TraceBreakpointKind.CommonSet.WRITE.kinds(), true, "");
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

	private void addSnap(TraceThread thread, Address address, int num, Address memRef,
			RefType refType) {
		TraceSnapshot snap = tb.trace.getTimeManager().createSnapshot(Integer.toString(num));
		snap.setEventThread(thread);
		TraceStack latestStack = tb.trace.getStackManager().getStack(thread, snap.getKey(), true);
		TraceStackFrame frame = latestStack.getFrame(0, 0, true);
		frame.setProgramCounter(Lifespan.nowOn(snap.getKey()), address);

		if (memRef != null) {
			tb.trace.getReferenceManager()
					.addMemoryReference(Lifespan.at(snap.getKey()), address, memRef, refType,
							SourceType.ANALYSIS, 0);
		}
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
	public void testCaptureBreakpointTimelinePluginSingleColumn() {
		performAction(provider.toggleGridOrColumnAction, true);
		captureIsolatedProvider(provider, 300, 300);
	}

	@Test
	public void testCaptureBreakpointTimelinePlugin() {
		captureIsolatedProvider(provider, 300, 300);
	}

	@Test
	public void testCaptureBreakpointTimelinePluginNoGrid() {
		performAction(provider.toggleGridAction, true);
		captureIsolatedProvider(provider, 300, 300);
	}
}
