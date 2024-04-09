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
package ghidra.debug.flatapi;

import static org.junit.Assert.*;

import java.util.Set;
import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServiceTestAccess;
import ghidra.app.script.GhidraState;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.breakpoint.LogicalBreakpoint.State;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class DeadFlatDebuggerAPITest extends AbstractFlatDebuggerAPITest<FlatDebuggerAPI> {

	protected class TestFlatAPI implements FlatDebuggerAPI {
		protected final GhidraState state =
			new GhidraState(env.getTool(), env.getProject(), program, null, null, null);

		@Override
		public GhidraState getState() {
			return state;
		}
	}

	@Override
	protected FlatDebuggerAPI newFlatAPI() {
		return new TestFlatAPI();
	}

	@Test
	public void testRequireService() throws Throwable {
		assertEquals(traceManager, api.requireService(DebuggerTraceManagerService.class));
	}

	interface NoSuchService {
	}

	@Test(expected = IllegalStateException.class)
	public void testRequireServiceAbsentErr() {
		api.requireService(NoSuchService.class);
	}

	@Test
	public void testGetCurrentDebuggerCoordinates() throws Throwable {
		assertSame(DebuggerCoordinates.NOWHERE, api.getCurrentDebuggerCoordinates());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		assertEquals(DebuggerCoordinates.NOWHERE.trace(tb.trace),
			api.getCurrentDebuggerCoordinates());
	}

	@Test
	public void testGetCurrentTrace() throws Throwable {
		assertNull(api.getCurrentTrace());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		assertEquals(tb.trace, api.getCurrentTrace());
	}

	@Test(expected = IllegalStateException.class)
	public void testRequireCurrentTraceAbsentErr() {
		api.requireCurrentTrace();
	}

	@Test
	public void testGetCurrentThread() throws Throwable {
		assertNull(api.getCurrentThread());

		createAndOpenTrace();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
		}
		waitForSwing();
		traceManager.activateTrace(tb.trace);

		assertEquals(thread, api.getCurrentThread());
	}

	@Test
	public void testGetCurrentView() throws Throwable {
		assertNull(api.getCurrentView());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		assertEquals(tb.trace.getProgramView(), api.getCurrentView());
	}

	@Test(expected = IllegalStateException.class)
	public void testRequireCurrentViewAbsentErr() {
		api.requireCurrentView();
	}

	@Test
	public void testGetCurrentFrame() throws Throwable {
		assertEquals(0, api.getCurrentFrame());

		createAndOpenTrace();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
			TraceStack stack = tb.trace.getStackManager().getStack(thread, 0, true);
			stack.setDepth(3, true);
		}
		waitForSwing();
		traceManager.activateThread(thread);
		traceManager.activateFrame(1);

		assertEquals(1, api.getCurrentFrame());
	}

	@Test
	public void testGetCurrentSnap() throws Throwable {
		assertEquals(0L, api.getCurrentSnap());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(1);

		assertEquals(1L, api.getCurrentSnap());
	}

	@Test
	public void testGetCurrentEmulationSchedule() throws Throwable {
		assertEquals(TraceSchedule.parse("0"), api.getCurrentEmulationSchedule());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(1);

		assertEquals(TraceSchedule.parse("1"), api.getCurrentEmulationSchedule());
	}

	@Test
	public void testActivateTrace() throws Throwable {
		createAndOpenTrace();
		api.activateTrace(tb.trace);

		assertEquals(tb.trace, traceManager.getCurrentTrace());
	}

	@Test
	public void testActivateTraceNull() throws Throwable {
		DebuggerTraceManagerServiceTestAccess.setEnsureActiveTrace(traceManager, false);
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertEquals(tb.trace, traceManager.getCurrentTrace());

		api.activateTrace(null);
		assertEquals(null, traceManager.getCurrentTrace());
	}

	@Test
	public void testActivateTraceNotOpen() throws Throwable {
		createTrace();
		assertFalse(traceManager.getOpenTraces().contains(tb.trace));

		api.activateTrace(tb.trace);

		assertTrue(traceManager.getOpenTraces().contains(tb.trace));
		assertEquals(tb.trace, traceManager.getCurrentTrace());
	}

	@Test
	public void testGetCurrentProgram() throws Throwable {
		assertEquals(null, api.getCurrentProgram());

		createProgram();
		programManager.openProgram(program);

		assertEquals(program, api.getCurrentProgram());
	}

	@Test(expected = IllegalStateException.class)
	public void testRequireCurrentProgramAbsentErr() throws Throwable {
		api.requireCurrentProgram();
	}

	@Test
	public void testActivateThread() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		api.activateThread(thread);

		assertEquals(thread, traceManager.getCurrentThread());
	}

	@Test
	public void testActivateThreadNull() throws Throwable {
		DebuggerTraceManagerServiceTestAccess.setEnsureActiveTrace(traceManager, false);
		api.activateThread(null);
		assertEquals(null, traceManager.getCurrentThread());

		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);
		waitForSwing();
		assertEquals(thread, traceManager.getCurrentThread());

		api.activateThread(null);
		assertNull(traceManager.getCurrentThread());
	}

	@Test
	public void testActivateThreadNotOpen() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(false);
		assertFalse(traceManager.getOpenTraces().contains(tb.trace));

		api.activateThread(thread);

		assertTrue(traceManager.getOpenTraces().contains(tb.trace));
		assertEquals(thread, traceManager.getCurrentThread());
	}

	@Test
	public void testActivateFrame() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);
		waitForSwing();
		api.activateFrame(1);

		assertEquals(1, traceManager.getCurrentFrame());
	}

	@Test
	public void testActivateSnap() throws Throwable {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		api.activateSnap(1);

		assertEquals(1L, traceManager.getCurrentSnap());
	}

	@Test
	public void testGetCurrentDebuggerAddress() throws Throwable {
		assertEquals(null, api.getCurrentDebuggerAddress());

		createTraceWithBinText();

		assertEquals(tb.addr(0x00400000), api.getCurrentDebuggerAddress());
	}

	@Test
	public void testGoToDynamic() throws Throwable {
		createTraceWithBinText();

		assertTrue(api.goToDynamic("00400123"));
		assertEquals(tb.addr(0x00400123), listingService.getCurrentLocation().getAddress());

		assertTrue(api.goToDynamic(tb.addr(0x00400321)));
		assertEquals(tb.addr(0x00400321), listingService.getCurrentLocation().getAddress());
	}

	@Test
	public void testTranslateStaticToDynamic() throws Throwable {
		createMappedTraceAndProgram();

		assertEquals(api.dynamicLocation("00400123"),
			api.translateStaticToDynamic(api.staticLocation("00400123")));
		assertNull(api.translateStaticToDynamic(api.staticLocation("00600123")));

		assertEquals(tb.addr(0x00400123), api.translateStaticToDynamic(addr(program, 0x00400123)));
		assertNull(api.translateStaticToDynamic(addr(program, 0x00600123)));
	}

	@Test
	public void testTranslateDynamicToStatic() throws Throwable {
		createMappedTraceAndProgram();

		assertEquals(api.staticLocation("00400123"),
			api.translateDynamicToStatic(api.dynamicLocation("00400123")));
		assertNull(api.translateDynamicToStatic(api.dynamicLocation("00600123")));

		assertEquals(addr(program, 0x00400123), api.translateDynamicToStatic(tb.addr(0x00400123)));
		assertNull(api.translateDynamicToStatic(tb.addr(0x00600123)));
	}

	@Test
	public void testEmulateLaunch() throws Throwable {
		Address entry = createEmulatableProgram();

		Trace trace = api.emulateLaunch(entry);
		assertEquals(trace, traceManager.getCurrentTrace());
	}

	@Test
	public void testEmulate() throws Throwable {
		Address entry = createEmulatableProgram();

		api.emulateLaunch(entry);
		TraceSchedule schedule =
			traceManager.getCurrent().getTime().steppedForward(traceManager.getCurrentThread(), 1);
		api.emulate(schedule, monitor);

		assertEquals(schedule, traceManager.getCurrent().getTime());
	}

	@Test
	public void testStepEmuInstruction() throws Throwable {
		Address entry = createEmulatableProgram();

		api.emulateLaunch(entry);
		TraceSchedule schedule =
			traceManager.getCurrent().getTime().steppedForward(traceManager.getCurrentThread(), 1);

		api.stepEmuInstruction(1, monitor);
		assertEquals(schedule, traceManager.getCurrent().getTime());

		api.stepEmuInstruction(-1, monitor);
		assertEquals(TraceSchedule.ZERO, traceManager.getCurrent().getTime());
	}

	@Test
	public void testStepEmuPcodeOp() throws Throwable {
		Address entry = createEmulatableProgram();

		api.emulateLaunch(entry);
		TraceSchedule schedule = traceManager.getCurrent()
				.getTime()
				.steppedPcodeForward(traceManager.getCurrentThread(), 1);

		api.stepEmuPcodeOp(1, monitor);
		assertEquals(schedule, traceManager.getCurrent().getTime());

		api.stepEmuPcodeOp(-1, monitor);
		assertEquals(TraceSchedule.ZERO, traceManager.getCurrent().getTime());
	}

	@Test
	public void testSkipEmuInstruction() throws Throwable {
		Address entry = createEmulatableProgram();

		api.emulateLaunch(entry);
		TraceSchedule schedule =
			traceManager.getCurrent().getTime().skippedForward(traceManager.getCurrentThread(), 1);

		api.skipEmuInstruction(1, monitor);
		assertEquals(schedule, traceManager.getCurrent().getTime());

		api.skipEmuInstruction(-1, monitor);
		assertEquals(TraceSchedule.ZERO, traceManager.getCurrent().getTime());
	}

	@Test
	public void testSkipEmuPcodeOp() throws Throwable {
		Address entry = createEmulatableProgram();

		api.emulateLaunch(entry);
		TraceSchedule schedule = traceManager.getCurrent()
				.getTime()
				.skippedPcodeForward(traceManager.getCurrentThread(), 1);

		api.skipEmuPcodeOp(1, monitor);
		assertEquals(schedule, traceManager.getCurrent().getTime());

		api.skipEmuPcodeOp(-1, monitor);
		assertEquals(TraceSchedule.ZERO, traceManager.getCurrent().getTime());
	}

	@Test
	public void testPatchEmu() throws Throwable {
		Address entry = createEmulatableProgram();

		api.emulateLaunch(entry);
		TraceSchedule schedule = traceManager.getCurrent()
				.getTime()
				.patched(traceManager.getCurrentThread(),
					traceManager.getCurrentPlatform().getLanguage(), "r0=0x321");

		api.patchEmu("r0=0x321", monitor);
		assertEquals(schedule, traceManager.getCurrent().getTime());

		api.stepEmuInstruction(-1, monitor);
		assertEquals(TraceSchedule.ZERO, traceManager.getCurrent().getTime());
	}

	@Test
	public void testSearchMemory() throws Throwable {
		createTraceWithBinText();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(tb.addr(0x00400003), api.searchMemory(tb.trace, 2, tb.range(0L, -1L),
			tb.arr(4, 5, 6, 7), null, true, monitor));
		assertEquals(tb.addr(0x00400003), api.searchMemory(tb.trace, 2, tb.range(0L, -1L),
			tb.arr(4, 5, 6, 7), tb.arr(-1, -1, -1, -1), true, monitor));
	}

	@Test
	public void testGetAllBreakpoints() throws Throwable {
		createProgramWithBreakpoint();

		assertEquals(1, api.getAllBreakpoints().size());
	}

	@Test
	public void testGetBreakpointsAt() throws Throwable {
		createProgramWithBreakpoint();

		assertEquals(1, api.getBreakpointsAt(api.staticLocation("00400000")).size());
		assertEquals(0, api.getBreakpointsAt(api.staticLocation("00400001")).size());
	}

	@Test
	public void testGetBreakpointsNamed() throws Throwable {
		createProgramWithBreakpoint();

		assertEquals(1, api.getBreakpointsNamed("name").size());
		assertEquals(0, api.getBreakpointsNamed("miss").size());
	}

	@Test
	public void testBreakpointsToggle() throws Throwable {
		createProgramWithBreakpoint();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		assertEquals(State.INEFFECTIVE_ENABLED, lb.computeState());
		assertEquals(Set.of(lb), api.breakpointsToggle(api.staticLocation("00400000")));
		assertEquals(State.INEFFECTIVE_DISABLED, lb.computeState());
	}

	@Test
	public void testBreakpointSetSoftwareExecute() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			api.breakpointSetSoftwareExecute(api.staticLocation("00400000"), "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.SW_EXECUTE, lb.getKinds());
		assertEquals(1, lb.getLength());
	}

	@Test
	public void testBreakpointSetHardwareExecute() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			api.breakpointSetHardwareExecute(api.staticLocation("00400000"), "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.HW_EXECUTE, lb.getKinds());
		assertEquals(1, lb.getLength());
	}

	@Test
	public void testBreakpointSetRead() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			api.breakpointSetRead(api.staticLocation("00400000"), 4, "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.READ, lb.getKinds());
		assertEquals(4, lb.getLength());
	}

	@Test
	public void testBreakpointSetWrite() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			api.breakpointSetWrite(api.staticLocation("00400000"), 4, "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.WRITE, lb.getKinds());
		assertEquals(4, lb.getLength());
	}

	@Test
	public void testBreakpointSetAccess() throws Throwable {
		createProgramWithText();

		LogicalBreakpoint lb = Unique.assertOne(
			api.breakpointSetAccess(api.staticLocation("00400000"), 4, "name"));
		assertEquals(addr(program, 0x00400000), lb.getAddress());
		assertEquals(TraceBreakpointKindSet.ACCESS, lb.getKinds());
		assertEquals(4, lb.getLength());
	}

	@Test
	public void testBreakpointsEnable() throws Throwable {
		createProgramWithBreakpoint();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());
		CompletableFuture<Void> changesSettled = breakpointService.changesSettled();
		waitOn(lb.disable());
		waitForSwing();
		waitOn(changesSettled);

		assertEquals(State.INEFFECTIVE_DISABLED, lb.computeState());
		assertEquals(Set.of(lb), api.breakpointsEnable(api.staticLocation("00400000")));
		assertEquals(State.INEFFECTIVE_ENABLED, lb.computeState());
	}

	@Test
	public void testBreakpointsDisable() throws Throwable {
		createProgramWithBreakpoint();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		assertEquals(State.INEFFECTIVE_ENABLED, lb.computeState());
		assertEquals(Set.of(lb), api.breakpointsDisable(api.staticLocation("00400000")));
		assertEquals(State.INEFFECTIVE_DISABLED, lb.computeState());
	}

	@Test
	public void testBreakpointsClear() throws Throwable {
		createProgramWithBreakpoint();
		LogicalBreakpoint lb = Unique.assertOne(breakpointService.getAllBreakpoints());

		assertTrue(api.breakpointsClear(api.staticLocation("00400000")));
		assertTrue(lb.isEmpty());
		assertEquals(0, breakpointService.getAllBreakpoints().size());
	}
}
