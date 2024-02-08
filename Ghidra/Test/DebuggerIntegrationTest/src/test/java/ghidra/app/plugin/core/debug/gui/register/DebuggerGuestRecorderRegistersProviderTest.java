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
package ghidra.app.plugin.core.debug.gui.register;

import java.io.IOException;
import java.util.Set;

import org.junit.Before;

import ghidra.app.plugin.core.debug.mapping.ObjectBasedDebuggerTargetTraceMapper;
import ghidra.dbg.target.TargetObject;
import ghidra.debug.api.model.DebuggerTargetTraceMapper;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;

public class DebuggerGuestRecorderRegistersProviderTest
		extends DebuggerRecorderRegistersProviderTest {

	@Override
	protected void createTrace() throws IOException {
		createTrace("DATA:BE:64:default");
	}

	@Before
	@Override
	public void setUpRegistersProviderTest() throws Exception {
		setUpGuestRegistersProviderTest();
	}

	@Override
	protected TracePlatform getPlatform() {
		return toy;
	}

	@Override
	protected void activateThread(TraceThread thread) {
		traceManager.activate(traceManager.resolveThread(thread).platform(toy));
	}

	@Override
	protected TargetObject chooseTarget() {
		return mb.testModel.session;
	}

	@Override
	protected DebuggerTargetTraceMapper createTargetTraceMapper(TargetObject target)
			throws Exception {
		return new ObjectBasedDebuggerTargetTraceMapper(target,
			new LanguageID("DATA:BE:64:default"), new CompilerSpecID("pointer64"), Set.of()) {
			@Override
			public TraceRecorder startRecording(PluginTool tool, Trace trace) {
				useTrace(trace);
				return super.startRecording(tool, trace);
			}
		};
	}

	@Override
	protected TraceRecorder recordAndWaitSync() throws Throwable {
		TraceRecorder recorder = super.recordAndWaitSync();
		createToyPlatform();
		return recorder;
	}
}
