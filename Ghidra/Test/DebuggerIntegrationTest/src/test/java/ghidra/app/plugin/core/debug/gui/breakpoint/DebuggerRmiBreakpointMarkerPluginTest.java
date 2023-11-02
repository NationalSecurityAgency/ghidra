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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import static org.junit.Assert.assertEquals;

import java.util.Map;
import java.util.Set;

import org.junit.experimental.categories.Category;

import db.Transaction;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.service.rmi.trace.TraceRmiTarget;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;

@Category(NightlyCategory.class)
public class DebuggerRmiBreakpointMarkerPluginTest
		extends AbstractDebuggerBreakpointMarkerPluginTest<TraceRmiTarget> {

	@Override
	protected TraceRmiTarget createLive() throws Throwable {
		createRmiConnection();
		addBreakpointMethods();
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			/**
			 * TODO: Various schema scenarios?:
			 * <ul>
			 * <li>per-session BreakpointContainer</li>
			 * <li>per-process BreakpointContainer</li>
			 * <li>spec-is-location</li>
			 * <li>spec-has-locations</li>
			 * <li>togglable locs</li>
			 * <li>non-togglable locs</li>
			 * <ul>
			 */
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
		}
		TraceRmiTarget target = rmiCx.publishTarget(tool, tb.trace);
		return target;
	}

	@Override
	protected Trace getTrace(TraceRmiTarget target) {
		return target.getTrace();
	}

	@Override
	protected void waitT(TraceRmiTarget target) throws Throwable {
		// No need to wait
	}

	@Override
	protected void addLiveMemoryAndBreakpoint(TraceRmiTarget target) throws Throwable {
		Lifespan zeroOn = Lifespan.nowOn(0);
		try (Transaction tx = tb.startTransaction()) {
			DBTraceObjectManager objs = tb.trace.getObjectManager();
			addMemoryRegion(objs, zeroOn, tb.range(0x55550000, 0x55550fff), "bin:.text", "rx");
			addBreakpointAndLoc(objs, zeroOn, tb.range(0x55550123),
				Set.of(TraceBreakpointKind.SW_EXECUTE));
		}
	}

	@Override
	protected void handleSetBreakpointInvocation(Set<TraceBreakpointKind> expectedKinds,
			long dynOffset) throws Throwable {
		Lifespan zeroOn = Lifespan.nowOn(0);
		if (TraceBreakpointKindSet.READ.equals(expectedKinds)) {
			Map<String, Object> args = rmiMethodSetReadBreak.expect();
			addBreakpointAndLoc(tb.trace.getObjectManager(), zeroOn, tb.range(dynOffset),
				TraceBreakpointKindSet.READ);
			rmiMethodSetReadBreak.result(null);
			assertEquals(Map.ofEntries(
				Map.entry("process", tb.obj("Processes[1]")),
				Map.entry("range", tb.range(dynOffset))), args);
		}
		else if (TraceBreakpointKindSet.WRITE.equals(expectedKinds)) {
			Map<String, Object> args = rmiMethodSetWriteBreak.expect();
			addBreakpointAndLoc(tb.trace.getObjectManager(), zeroOn, tb.range(dynOffset),
				TraceBreakpointKindSet.WRITE);
			rmiMethodSetWriteBreak.result(null);
			assertEquals(Map.ofEntries(
				Map.entry("process", tb.obj("Processes[1]")),
				Map.entry("range", tb.range(dynOffset))), args);
		}
		else if (TraceBreakpointKindSet.ACCESS.equals(expectedKinds)) {
			Map<String, Object> args = rmiMethodSetAccessBreak.expect();
			addBreakpointAndLoc(tb.trace.getObjectManager(), zeroOn, tb.range(dynOffset),
				TraceBreakpointKindSet.ACCESS);
			rmiMethodSetAccessBreak.result(null);
			assertEquals(Map.ofEntries(
				Map.entry("process", tb.obj("Processes[1]")),
				Map.entry("range", tb.range(dynOffset))), args);
		}
		else if (TraceBreakpointKindSet.SW_EXECUTE.equals(expectedKinds)) {
			Map<String, Object> args = rmiMethodSetSwBreak.expect();
			addBreakpointAndLoc(tb.trace.getObjectManager(), zeroOn, tb.range(dynOffset),
				TraceBreakpointKindSet.SW_EXECUTE);
			rmiMethodSetSwBreak.result(null);
			assertEquals(Map.ofEntries(
				Map.entry("process", tb.obj("Processes[1]")),
				Map.entry("address", tb.addr(dynOffset))), args);
		}
		else if (TraceBreakpointKindSet.HW_EXECUTE.equals(expectedKinds)) {
			Map<String, Object> args = rmiMethodSetHwBreak.expect();
			addBreakpointAndLoc(tb.trace.getObjectManager(), zeroOn, tb.range(dynOffset),
				TraceBreakpointKindSet.HW_EXECUTE);
			rmiMethodSetHwBreak.result(null);
			assertEquals(Map.ofEntries(
				Map.entry("process", tb.obj("Processes[1]")),
				Map.entry("address", tb.addr(dynOffset))), args);
		}
		else {
			throw new AssertionError("Unhandled invocation for kinds: " + expectedKinds);
		}
	}

	@Override
	protected void handleToggleBreakpointInvocation(TraceBreakpoint expectedBreakpoint,
			boolean expectedEn) throws Throwable {
		if (!(expectedBreakpoint instanceof TraceObjectBreakpointLocation loc)) {
			throw new AssertionError("Unexpected trace breakpoint type: " + expectedBreakpoint);
		}
		Map<String, Object> args = rmiMethodToggleBreak.expect();
		try (Transaction tx = tb.startTransaction()) {
			loc.setEnabled(Lifespan.nowOn(0), expectedEn);
		}
		rmiMethodToggleBreak.result(null);
		assertEquals(Map.ofEntries(
			Map.entry("breakpoint", loc.getSpecification().getObject()),
			Map.entry("enabled", expectedEn)), args);
	}

	@Override
	protected void handleDeleteBreakpointInvocation(TraceBreakpoint expectedBreakpoint)
			throws Throwable {
		if (!(expectedBreakpoint instanceof TraceObjectBreakpointLocation loc)) {
			throw new AssertionError("Unexpected trace breakpoint type: " + expectedBreakpoint);
		}
		Map<String, Object> args = rmiMethodDeleteBreak.expect();
		try (Transaction tx = tb.startTransaction()) {
			loc.getObject().remove(Lifespan.nowOn(0));
		}
		rmiMethodDeleteBreak.result(null);
		assertEquals(Map.ofEntries(
			Map.entry("breakpoint", loc.getSpecification().getObject())), args);
	}
}
