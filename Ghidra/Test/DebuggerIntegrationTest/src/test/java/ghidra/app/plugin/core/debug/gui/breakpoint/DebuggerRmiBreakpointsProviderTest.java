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

import java.util.*;

import org.junit.Before;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiTarget;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;

public class DebuggerRmiBreakpointsProviderTest
		extends AbstractDebuggerBreakpointsProviderTest<TraceRmiTarget, Trace> {

	ToyDBTraceBuilder tb3;

	@Before
	public void setUpRmiBreakpointServiceTest() throws Throwable {
		createRmiConnection();
		addBreakpointMethods();
	}

	@Override
	protected TraceRmiTarget createTarget1() throws Throwable {
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
			ensureBreakpointContainer(tb.trace.getObjectManager());
		}
		return rmiCx.publishTarget(tool, tb.trace);
	}

	@Override
	protected TraceRmiTarget createTarget3() throws Throwable {
		tb3 = new ToyDBTraceBuilder("dynamic3-" + name.getMethodName(), LANGID_TOYBE64);
		try (Transaction tx = tb3.startTransaction()) {
			tb3.trace.getTimeManager().createSnapshot("Fist snapshot");
			tb3.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb3.createObjectsProcessAndThreads();
			ensureBreakpointContainer(tb3.trace.getObjectManager());
		}
		return rmiCx.publishTarget(tool, tb3.trace);
	}

	@Override
	protected Trace getProcess1() {
		return tb.trace;
	}

	@Override
	protected Trace getProcess3() {
		return tb3.trace;
	}

	@Override
	protected Trace getTrace(TraceRmiTarget target) {
		return target.getTrace();
	}

	@Override
	protected void waitTarget(TraceRmiTarget target) throws Throwable {
		waitForDomainObject(target.getTrace());
	}

	@Override
	protected void addLiveMemory(Trace trace) throws Throwable {
		try (Transaction tx = trace.openTransaction("Add .text")) {
			Objects.requireNonNull(addMemoryRegion(trace.getObjectManager(), Lifespan.nowOn(0),
				tb.range(0x55550000, 0x55550fff), "bin:.text", "rx")
						.queryInterface(TraceObjectMemoryRegion.class));
		}
	}

	@Override
	protected void addLiveBreakpoint(TraceRmiTarget target, long offset) throws Throwable {
		Trace trace = target.getTrace();
		try (Transaction tx = trace.openTransaction("Add breakpoint")) {
			addBreakpointAndLoc(trace.getObjectManager(), Lifespan.nowOn(0), tb.range(offset),
				TraceBreakpointKindSet.SW_EXECUTE);
		}
	}

	@Override
	protected void handleSetBreakpointInvocation(Set<TraceBreakpointKind> expectedKinds,
			long dynOffset) throws Throwable {
		Lifespan zeroOn = Lifespan.nowOn(0);
		if (TraceBreakpointKindSet.SW_EXECUTE.equals(expectedKinds)) {
			Map<String, Object> args = rmiMethodSetSwBreak.expect();
			addBreakpointAndLoc(tb.trace.getObjectManager(), zeroOn, tb.range(dynOffset),
				TraceBreakpointKindSet.SW_EXECUTE);
			rmiMethodSetSwBreak.result(null);
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
	protected void assertNotLiveBreakpoint(TraceRmiTarget target, TraceBreakpoint breakpoint)
			throws Throwable {
		// TODO: Not sure there's anything to do here
	}
}
