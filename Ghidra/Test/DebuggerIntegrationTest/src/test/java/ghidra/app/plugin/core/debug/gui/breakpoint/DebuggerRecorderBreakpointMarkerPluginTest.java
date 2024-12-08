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

import java.util.Set;
import java.util.concurrent.*;

import org.junit.experimental.categories.Category;

import generic.test.category.NightlyCategory;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.debug.api.action.ActionSource;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerRecorderBreakpointMarkerPluginTest
		extends AbstractDebuggerBreakpointMarkerPluginTest<TraceRecorder> {

	@Override
	protected TraceRecorder createLive() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		waitRecorder(recorder);
		return recorder;
	}

	@Override
	protected Trace getTrace(TraceRecorder recorder) {
		return recorder.getTrace();
	}

	@Override
	protected void waitT(TraceRecorder recorder) throws Throwable {
		waitRecorder(recorder);
	}

	@Override
	protected void addLiveMemoryAndBreakpoint(TraceRecorder recorder)
			throws InterruptedException, ExecutionException, TimeoutException {
		mb.testProcess1.addRegion("bin:.text", mb.rng(0x55550000, 0x55550fff), "rx");
		TargetBreakpointSpecContainer cont = getBreakpointContainer(recorder);
		cont.placeBreakpoint(mb.addr(0x55550123), Set.of(TargetBreakpointKind.SW_EXECUTE))
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	@Override
	protected void handleSetBreakpointInvocation(Set<TraceBreakpointKind> expectedKinds,
			long dynOffset) {
		// The logic is already embedded in the Test model
	}

	@Override
	protected void handleToggleBreakpointInvocation(TraceBreakpoint expectedBreakpoint,
			boolean expectedEn) throws Throwable {
		// The logic is already embedded in the Test model
	}

	@Override
	protected void handleDeleteBreakpointInvocation(TraceBreakpoint expectedBreakpoint)
			throws Throwable {
		// The logic is already embedded in the Test model
	}
}
