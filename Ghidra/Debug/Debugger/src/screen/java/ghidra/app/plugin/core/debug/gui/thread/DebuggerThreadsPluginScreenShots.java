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

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest.TestDebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceProxyPlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.model.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerThreadsPluginScreenShots extends GhidraScreenShotGenerator {

	// NOTE: Using model builder to capture "recording" icon in tabs
	TestDebuggerModelBuilder mb = new TestDebuggerModelBuilder();
	DebuggerModelServiceProxyPlugin modelService;
	DebuggerTraceManagerService traceManager;
	DebuggerThreadsPlugin threadsPlugin;

	@Before
	public void setUpMine() throws Throwable {
		modelService = addPlugin(tool, DebuggerModelServiceProxyPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		threadsPlugin = addPlugin(tool, DebuggerThreadsPlugin.class);
	}

	protected boolean nullOrDead(TraceThread thread) {
		return thread == null || !thread.isAlive();
	}

	@Test
	public void testCaptureDebuggerThreadsPlugin() throws Throwable {
		mb.createTestModel();
		TestTargetProcess process = mb.testModel.addProcess(1234);

		TraceRecorder recorder =
			modelService.recordTarget(process, new TestDebuggerTargetTraceMapper(process));
		Trace trace = recorder.getTrace();

		TestTargetThread mainThread = process.addThread(1);
		waitForValue(() -> recorder.getTraceThread(mainThread));
		recorder.forceSnapshot();
		TestTargetThread serverThread = process.addThread(2);
		waitForValue(() -> recorder.getTraceThread(serverThread));
		recorder.forceSnapshot();
		recorder.forceSnapshot();
		TestTargetThread handler1Thread = process.addThread(3);
		waitForValue(() -> recorder.getTraceThread(handler1Thread));
		recorder.forceSnapshot();
		recorder.forceSnapshot();
		TestTargetThread handler2Thread = process.addThread(4);
		waitForValue(() -> recorder.getTraceThread(handler2Thread));
		AbstractGhidraHeadedDebuggerGUITest.waitForDomainObject(trace);

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Comments", true)) {
			recorder.getTraceThread(mainThread).setComment("GUI main loop");
			recorder.getTraceThread(serverThread).setComment("Server");
			recorder.getTraceThread(handler1Thread).setComment("Handler 1");
			recorder.getTraceThread(handler2Thread).setComment("Handler 2");
		}

		recorder.forceSnapshot();
		process.removeThreads(handler1Thread);
		waitFor(() -> nullOrDead(recorder.getTraceThread(handler1Thread)));
		recorder.forceSnapshot();
		recorder.forceSnapshot();
		recorder.forceSnapshot();
		process.removeThreads(handler2Thread);
		waitFor(() -> nullOrDead(recorder.getTraceThread(handler2Thread)));
		long lastSnap = recorder.forceSnapshot().getKey();

		traceManager.openTrace(trace);
		traceManager.activateThread(recorder.getTraceThread(serverThread));
		traceManager.activateSnap(lastSnap);

		TestTargetProcess dummy1 = mb.testModel.addProcess(4321);
		TestTargetProcess dummy2 = mb.testModel.addProcess(5432);
		TraceRecorder recDummy1 =
			modelService.recordTarget(dummy1, new TestDebuggerTargetTraceMapper(dummy1));
		TraceRecorder recDummy2 =
			modelService.recordTarget(dummy2, new TestDebuggerTargetTraceMapper(dummy2));

		traceManager.setAutoCloseOnTerminate(false);

		traceManager.openTrace(recDummy1.getTrace());
		traceManager.openTrace(recDummy2.getTrace());
		recDummy1.stopRecording();

		captureIsolatedProvider(DebuggerThreadsProvider.class, 900, 300);
	}
}
