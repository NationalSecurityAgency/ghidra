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

import static org.junit.Assert.assertNull;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import ghidra.dbg.model.TestTargetProcess;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.debug.api.action.ActionSource;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;

public class DebuggerRecorderBreakpointsProviderTest
		extends AbstractDebuggerBreakpointsProviderTest<TraceRecorder, TestTargetProcess> {

	@Override
	protected TraceRecorder createTarget1() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		return modelService.recordTarget(mb.testProcess1, createTargetTraceMapper(mb.testProcess1),
			ActionSource.AUTOMATIC);
	}

	@Override
	protected TraceRecorder createTarget3() throws Throwable {
		return modelService.recordTarget(mb.testProcess3, createTargetTraceMapper(mb.testProcess3),
			ActionSource.AUTOMATIC);
	}

	@Override
	protected TestTargetProcess getProcess1() {
		return mb.testProcess1;
	}

	@Override
	protected TestTargetProcess getProcess3() {
		return mb.testProcess3;
	}

	@Override
	protected Trace getTrace(TraceRecorder recorder) {
		return recorder.getTrace();
	}

	@Override
	protected void waitTarget(TraceRecorder recorder) throws Throwable {
		waitRecorder(recorder);
	}

	@Override
	protected void addLiveMemory(TestTargetProcess process) throws Exception {
		process.addRegion("bin:.text", mb.rng(0x55550000, 0x55550fff), "rx");
	}

	@Override
	protected void addLiveBreakpoint(TraceRecorder recorder, long offset) throws Exception {
		TargetBreakpointSpecContainer cont = getBreakpointContainer(recorder);
		cont.placeBreakpoint(mb.addr(offset), Set.of(TargetBreakpointKind.SW_EXECUTE))
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	@Override
	protected void handleSetBreakpointInvocation(Set<TraceBreakpointKind> expectedKinds,
			long dynOffset) throws Throwable {
		// Logic already in Test model
	}

	@Override
	protected void handleToggleBreakpointInvocation(TraceBreakpoint expectedBreakpoint,
			boolean expectedEnabled) throws Throwable {
		// Logic already in Test model
	}

	@Override
	protected void assertNotLiveBreakpoint(TraceRecorder recorder, TraceBreakpoint breakpoint)
			throws Throwable {
		assertNull(recorder.getTargetBreakpoint(breakpoint));
	}
}
