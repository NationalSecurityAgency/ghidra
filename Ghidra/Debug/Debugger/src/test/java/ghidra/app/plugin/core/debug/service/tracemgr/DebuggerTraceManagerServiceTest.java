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
package ghidra.app.plugin.core.debug.service.tracemgr;

import static org.junit.Assert.*;

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceTest;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.model.TestTargetStack;
import ghidra.dbg.model.TestTargetStackFrameHasRegisterBank;
import ghidra.framework.model.DomainFile;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace;
import ghidra.util.SystemUtilities;
import ghidra.util.database.UndoableTransaction;

public class DebuggerTraceManagerServiceTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	static {
		DebuggerModelServiceTest.addTestModelPathPatterns();
	}

	@Test
	public void testGetOpenTraces() throws Exception {
		assertEquals(Set.of(), traceManager.getOpenTraces());

		createAndOpenTrace();
		waitForDomainObject(tb.trace);

		assertEquals(Set.of(tb.trace), traceManager.getOpenTraces());

		traceManager.closeTrace(tb.trace);
		waitForSwing();

		assertEquals(Set.of(), traceManager.getOpenTraces());
	}

	@Test
	public void testGetCurrent() throws Exception {
		assertEquals(DebuggerCoordinates.NOWHERE, traceManager.getCurrent());

		createTrace();
		waitForDomainObject(tb.trace);

		assertEquals(DebuggerCoordinates.NOWHERE, traceManager.getCurrent());

		traceManager.openTrace(tb.trace);
		waitForSwing();

		assertEquals(DebuggerCoordinates.NOWHERE, traceManager.getCurrent());

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(tb.trace, traceManager.getCurrent().getTrace());
	}

	@Test
	public void testGetCurrentView() throws Exception {
		assertNull(traceManager.getCurrentView());

		createTrace();
		waitForDomainObject(tb.trace);

		assertNull(traceManager.getCurrentView());

		traceManager.openTrace(tb.trace);
		waitForSwing();

		assertNull(traceManager.getCurrentView());

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(tb.trace, traceManager.getCurrentView().getTrace());
		assertEquals(tb.trace.getProgramView(), traceManager.getCurrentView());
	}

	@Test
	public void testGetCurrentThread() throws Exception {
		assertNull(traceManager.getCurrentThread());

		createTrace();
		waitForDomainObject(tb.trace);

		assertNull(traceManager.getCurrentThread());

		traceManager.openTrace(tb.trace);
		waitForSwing();

		assertNull(traceManager.getCurrentThread());

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertNull(traceManager.getCurrentThread());

		DBTraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			thread = tb.getOrAddThread("Thread 1", 0);
		}
		waitForDomainObject(tb.trace);

		assertEquals(thread, traceManager.getCurrentThread());

		traceManager.activateTrace(null);
		waitForSwing();

		assertNull(traceManager.getCurrentTrace());
		assertEquals(thread, traceManager.getCurrentThreadFor(tb.trace));

		traceManager.closeTrace(tb.trace);
		waitForSwing();

		assertNull(traceManager.getCurrentThreadFor(tb.trace));
	}

	@Test
	public void testGetCurrentSnap() throws Exception {
		assertEquals(0, traceManager.getCurrentSnap());

		createTrace();
		waitForDomainObject(tb.trace);

		assertEquals(0, traceManager.getCurrentSnap());

		traceManager.openTrace(tb.trace);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentSnap());

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentSnap());

		traceManager.activateSnap(5);
		waitForSwing();

		assertEquals(5, traceManager.getCurrentSnap());

		traceManager.activateTrace(null);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentSnap());
	}

	@Test
	public void testGetCurrentFrame() throws Exception {
		assertEquals(0, traceManager.getCurrentFrame());

		createTrace();
		waitForDomainObject(tb.trace);

		assertEquals(0, traceManager.getCurrentFrame());

		traceManager.openTrace(tb.trace);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentFrame());

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentFrame());

		traceManager.activateFrame(5);
		waitForSwing();

		assertEquals(5, traceManager.getCurrentFrame());

		traceManager.activateTrace(null);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentFrame());
	}

	@Test
	public void testOpenTrace() throws Exception {
		createTrace();
		waitForDomainObject(tb.trace);

		assertEquals(Set.of(), traceManager.getOpenTraces());
		assertEquals(Set.of(tb), Set.copyOf(tb.trace.getConsumerList()));

		traceManager.openTrace(tb.trace);
		waitForSwing();

		assertEquals(Set.of(tb, traceManager), Set.copyOf(tb.trace.getConsumerList()));
	}

	// TODO: Test the other close methods: all, others, dead

	@Test
	public void testOpenTraceDomainFile() throws Exception {
		createTrace();
		waitForDomainObject(tb.trace);

		assertEquals(Set.of(), traceManager.getOpenTraces());
		assertEquals(Set.of(tb), Set.copyOf(tb.trace.getConsumerList()));

		traceManager.openTrace(tb.trace.getDomainFile(), DomainFile.DEFAULT_VERSION);
		waitForSwing();

		assertEquals(Set.of(tb, traceManager), Set.copyOf(tb.trace.getConsumerList()));
	}

	@Test
	public void testOpenTraceDomainFileWrongType() throws Exception {
		createProgram();
		waitForDomainObject(program);

		assertEquals(Set.of(), traceManager.getOpenTraces());
		assertEquals(Set.of(this), Set.copyOf(program.getConsumerList()));

		try {
			traceManager.openTrace(program.getDomainFile(), DomainFile.DEFAULT_VERSION);
			fail();
		}
		catch (ClassCastException e) {
			// pass
		}
		waitForSwing();

		assertEquals(Set.of(this), Set.copyOf(program.getConsumerList()));
	}

	@Test
	public void testOpenTraces() throws Exception {
		createTrace();
		createProgram();
		waitForDomainObject(tb.trace);
		waitForDomainObject(program);

		Collection<Trace> result =
			traceManager.openTraces(Set.of(tb.trace.getDomainFile(), program.getDomainFile()));
		assertEquals(Set.of(tb.trace), Set.copyOf(result));

		assertEquals(Set.of(tb, traceManager), Set.copyOf(tb.trace.getConsumerList()));
		assertEquals(Set.of(this), Set.copyOf(program.getConsumerList()));
	}

	@Test
	public void testSaveTrace() throws Exception {
		createTrace();
		waitForDomainObject(tb.trace);

		assertFalse(tb.trace.getDomainFile().getPathname().contains("New Traces"));

		// Technically doesn't have to be open in the manager
		traceManager.saveTrace(tb.trace);
		waitForDomainObject(tb.trace);

		assertTrue(tb.trace.getDomainFile().getPathname().contains("New Traces"));
	}

	@Test
	public void testCloseTrace() throws Exception {
		createAndOpenTrace();
		waitForDomainObject(tb.trace);

		assertEquals(Set.of(tb, traceManager), Set.copyOf(tb.trace.getConsumerList()));

		traceManager.closeTrace(tb.trace);
		waitForSwing();

		assertEquals(Set.of(tb), Set.copyOf(tb.trace.getConsumerList()));
		assertEquals(Set.of(), traceManager.getOpenTraces());
	}

	@Test
	public void testAutoActivatePresent() throws Exception {
		assertTrue(traceManager.isAutoActivatePresent());

		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		traceManager.openTrace(trace);
		traceManager.activateTrace(trace);
		waitForSwing();

		assertEquals(0, recorder.getSnap());
		assertEquals(0, traceManager.getCurrentSnap());

		recorder.forceSnapshot();
		waitForSwing();

		assertEquals(1, recorder.getSnap());
		assertEquals(1, traceManager.getCurrentSnap());

		traceManager.setAutoActivatePresent(false);

		recorder.forceSnapshot();
		waitForSwing();

		assertEquals(2, recorder.getSnap());
		assertEquals(1, traceManager.getCurrentSnap());

		traceManager.setAutoActivatePresent(true);

		recorder.forceSnapshot();
		waitForSwing();

		assertEquals(3, recorder.getSnap());
		assertEquals(3, traceManager.getCurrentSnap());
	}

	@Test
	public void testSynchronizeFocusTraceToModel() throws Exception {
		assertTrue(traceManager.isSynchronizeFocus());

		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		traceManager.openTrace(trace);
		waitForSwing();

		assertNull(mb.testModel.session.getFocus());

		traceManager.activateTrace(trace);
		waitForSwing();

		// No default thread/frame when live with focus support
		assertNull(traceManager.getCurrentThread());
		assertEquals(mb.testProcess1, mb.testModel.session.getFocus());

		traceManager.activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		assertEquals(mb.testThread1, mb.testModel.session.getFocus());

		TestTargetStack stack = mb.testThread1.addStack();
		// Note, push simply moves the data, the new frame still has the higher index
		TestTargetStackFrameHasRegisterBank frame0 = stack.pushFrameHasBank();
		TestTargetStackFrameHasRegisterBank frame1 = stack.pushFrameHasBank();
		waitForDomainObject(trace);

		// Starting with 0 results in no change in coordinates, so ignored
		traceManager.activateFrame(1);
		waitForSwing();

		assertEquals(frame1, mb.testModel.session.getFocus());

		traceManager.activateFrame(0);
		waitForSwing();

		assertEquals(frame0, mb.testModel.session.getFocus());

		traceManager.setSynchronizeFocus(false);
		traceManager.activateFrame(1);
		waitForSwing();

		assertEquals(frame0, mb.testModel.session.getFocus());
	}

	@Test
	@Ignore("TODO") // Not sure why this fails under Gradle but not my IDE
	public void testSynchronizeFocusModelToTrace() throws Exception {
		assertTrue(traceManager.isSynchronizeFocus());

		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		traceManager.openTrace(trace);
		waitForSwing();

		assertNull(traceManager.getCurrentTrace());

		mb.testModel.session.requestFocus(mb.testProcess1)
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForSwing();

		// No default thread/frame when live with focus support
		assertNull(traceManager.getCurrentThread());
		assertEquals(recorder.getTrace(), traceManager.getCurrentTrace());

		mb.testModel.session.requestFocus(mb.testThread1)
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForSwing();

		assertEquals(recorder.getTraceThread(mb.testThread1), traceManager.getCurrentThread());

		TestTargetStack stack = mb.testThread1.addStack();
		// Note, push simply moves the data, the new frame still has the higher index
		TestTargetStackFrameHasRegisterBank frame0 = stack.pushFrameHasBank();
		TestTargetStackFrameHasRegisterBank frame1 = stack.pushFrameHasBank();
		waitForDomainObject(trace);

		// Starting with 0 results in no change in coordinates, so ignored
		mb.testModel.session.requestFocus(frame1)
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForSwing();

		assertEquals(1, traceManager.getCurrentFrame());

		mb.testModel.session.requestFocus(frame0)
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentFrame());

		traceManager.setSynchronizeFocus(false);
		mb.testModel.session.requestFocus(frame1)
				.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentFrame());
	}
}
