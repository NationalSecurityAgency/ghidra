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
package ghidra.app.plugin.core.debug.service.breakpoint;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.junit.Before;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.dbg.model.TestTargetMemoryRegion;
import ghidra.dbg.model.TestTargetProcess;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.debug.api.action.ActionSource;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceStaticMapping;

public class DebuggerRecorderLogicalBreakpointServiceTest extends
		AbstractDebuggerLogicalBreakpointServiceTest<TraceRecorder, TestTargetMemoryRegion> {

	@Before
	public void setUpRecorderBreakpointServiceTest() throws Throwable {
		// NOTE: Traces derive from recordings, not toy builder
		// NOTE: Program must be saved into project so it has a URL for mappings
		createTestModel();
		mb.createTestProcessesAndThreads();
	}

	@Override
	protected void createTarget1() throws Throwable {
		target1 = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
	}

	@Override
	protected void createTarget3() throws Throwable {
		target3 = modelService.recordTarget(mb.testProcess3,
			createTargetTraceMapper(mb.testProcess3), ActionSource.AUTOMATIC);
	}

	@Override
	protected Trace getTrace(TraceRecorder recorder) {
		return recorder.getTrace();
	}

	@Override
	protected void simulateTargetStep(TraceRecorder recorder) throws Throwable {
		assertEquals(target1, recorder); // In case I ever pass in target3, scream.
		mb.testModel.session.simulateStep(mb.testThread1);
		waitRecorder(recorder);
	}

	@Override
	protected long getSnap(TraceRecorder recorder) {
		return recorder.getSnap();
	}

	@Override
	protected boolean isTargetValid(TraceRecorder recorder) {
		return recorder.isRecording();
	}

	protected TestTargetMemoryRegion addTargetTextRegion(TestTargetProcess p, long offset) {
		return p.addRegion("bin:.text", mb.rng(offset, offset + 0x0fff), "rx");
	}

	protected TestTargetMemoryRegion addTargetDataRegion(TestTargetProcess p) {
		return p.addRegion("bin:.data", mb.rng(0x56550000, 0x5655ffff), "rw");
	}

	protected TestTargetProcess getProcess(TraceRecorder recorder) {
		if (recorder == target1) {
			return mb.testProcess1;
		}
		if (recorder == target3) {
			return mb.testProcess3;
		}
		throw new AssertionError();
	}

	@Override
	protected TestTargetMemoryRegion addTargetTextRegion(TraceRecorder recorder, long offset) {
		return addTargetTextRegion(getProcess(recorder), offset);
	}

	@Override
	protected TestTargetMemoryRegion addTargetTextRegion(TraceRecorder recorder) {
		return addTargetTextRegion(getProcess(recorder), 0x55550000);
	}

	@Override
	protected TestTargetMemoryRegion addTargetDataRegion(TraceRecorder recorder) throws Throwable {
		return addTargetDataRegion(getProcess(recorder));
	}

	@Override
	protected void addTextMapping(TraceRecorder r, TestTargetMemoryRegion region, Program p)
			throws Throwable {
		Trace t = r.getTrace();
		TraceMemoryRegion textRegion =
			waitFor(() -> r.getTraceMemoryRegion(region), "Recorder missed region: " + region);
		try (Transaction tx = t.openTransaction("Add .text mapping")) {
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(t, null, textRegion.getLifespan(),
					textRegion.getMinAddress()),
				new ProgramLocation(p, addr(p, 0x00400000)), 0x1000,
				false);
		}
	}

	@Override
	protected void removeTextMapping(TraceRecorder r, Program p) throws Throwable {
		Trace t = r.getTrace();
		try (Transaction tx = t.openTransaction("Remove .text mapping")) {
			TraceStaticMapping mapping =
				t.getStaticMappingManager().findContaining(addr(t, 0x55550000), r.getSnap());
			mapping.delete();
		}
	}

	@Override
	protected void addTargetAccessBreakpoint(TraceRecorder r, TestTargetMemoryRegion region)
			throws Throwable {
		TraceMemoryRegion traceRegion =
			waitFor(() -> r.getTraceMemoryRegion(region), "Recorder missed region: " + region);
		long offset = traceRegion.getMinAddress().getOffset() + 0x0123;
		TargetBreakpointSpecContainer cont = getBreakpointContainer(r);
		waitOn(cont.placeBreakpoint(mb.addr(offset),
			Set.of(TargetBreakpointKind.READ, TargetBreakpointKind.WRITE)));
		waitRecorder(r);
	}

	@Override
	protected void addTargetSoftwareBreakpoint(TraceRecorder r, TestTargetMemoryRegion region)
			throws Throwable {
		TraceMemoryRegion traceRegion =
			waitFor(() -> r.getTraceMemoryRegion(region), "Recorder missed region: " + region);
		long offset = traceRegion.getMinAddress().getOffset() + 0x0123;
		TargetBreakpointSpecContainer cont = getBreakpointContainer(r);
		waitOn(cont.placeBreakpoint(mb.addr(offset), Set.of(TargetBreakpointKind.SW_EXECUTE)));
		waitRecorder(r);
	}

	@Override
	protected void removeTargetSoftwareBreakpoint(TraceRecorder r) throws Throwable {
		TargetBreakpointSpecContainer cont = getBreakpointContainer(r);
		cont.fetchElements().thenAccept(elements -> {
			for (TargetObject obj : elements.values()) {
				if (!(obj instanceof TargetBreakpointSpec) ||
					!(obj instanceof TargetDeletable)) {
					continue;
				}
				TargetBreakpointSpec spec = (TargetBreakpointSpec) obj;
				if (!spec.getKinds().contains(TargetBreakpointKind.SW_EXECUTE)) {
					continue;
				}
				TargetDeletable del = (TargetDeletable) obj;
				del.delete();
				return;
			}
			fail("No deletable software breakpoint spec found");
		}).get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	@Override
	protected void terminateTarget(TraceRecorder recorder) {
		recorder.stopRecording();
	}

	@Override
	protected TraceBreakpoint findLoc(Set<TraceBreakpoint> locs, int index) {
		return locs.stream()
				.filter(b -> b.getName().equals(Integer.toString(index)))
				.findAny()
				.orElseThrow();
	}

	@Override
	protected void handleToggleBreakpointInvocation(TraceBreakpoint expectedBreakpoint,
			boolean expectedEnabled) throws Throwable {
		// Logic is in the Test model
	}

	@Override
	protected void handleDeleteBreakpointInvocation(TraceBreakpoint expectedBreakpoint)
			throws Throwable {
		// Logic is in the Test model
	}
}
