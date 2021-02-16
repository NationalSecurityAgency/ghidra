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
package ghidra.app.plugin.core.debug.service.model;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.debug.event.ModelObjectFocusedPluginEvent;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncPairingQueue;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.model.TestDebuggerObjectModel;
import ghidra.dbg.model.TestLocalDebuggerModelFactory;
import ghidra.dbg.util.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.CollectionChangeListener;
import mockit.Mocked;
import mockit.VerificationsInOrder;

/**
 * TODO: Cover the error cases, and cases where {@code null} is expected
 * 
 * TODO: Cover cases where multiple recorders are present
 */
public class DebuggerModelServiceTest extends AbstractGhidraHeadedDebuggerGUITest
		implements DebuggerModelTestUtils {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	public static void addTestModelPathPatterns() {
		PathMatcher m = DefaultTraceRecorder.HARDCODED_MATCHER;
		m.addPattern(PathUtils.parse("Processes[]"));
		m.addPattern(PathUtils.parse("Processes[].Breakpoints[]"));
		m.addPattern(PathUtils.parse("Processes[].Memory[]"));
		m.addPattern(PathUtils.parse("Processes[].Modules[]"));
		m.addPattern(PathUtils.parse("Processes[].Registers[]"));
		m.addPattern(PathUtils.parse("Processes[].Threads[]"));
		m.addPattern(PathUtils.parse("Processes[].Threads[].RegisterBank"));
		m.addPattern(PathUtils.parse("Processes[].Threads[].Stack[]"));
		m.addPattern(PathUtils.parse("Processes[].Threads[].Stack[].RegisterBank"));
	}

	static {
		addTestModelPathPatterns();
	}

	/**
	 * Exists just for mocking, because jmockit does Bad Things (TM) to
	 * CollectionChangeListener.of() if I try to mock one of those or a subclass directly. I'm
	 * guessing the version we're using (1.44 as of this writing) is utterly ignorant of static
	 * interface methods. What was the latest version of Java at the time?
	 * 
	 * <p>
	 * TODO: Check if a later version fixes this issue. If so, consider upgrading. If not, submit an
	 * issue.
	 */
	interface CollectionChangeDelegate<E> {
		void elementAdded(E element);

		void elementRemoved(E element);
	}

	static class CollectionChangeDelegateWrapper<E>
			implements CollectionChangeListener<E> {
		protected final CollectionChangeDelegate<E> delegate;

		public CollectionChangeDelegateWrapper(CollectionChangeDelegate<E> delegate) {
			assertNotNull("Did you remember the jmockit agent?", delegate);
			this.delegate = delegate;
		}

		@Override
		public void elementAdded(E element) {
			delegate.elementAdded(element);
		}

		@Override
		public void elementRemoved(E element) {
			delegate.elementRemoved(element);
		}

		@Override
		public void elementModified(E element) {
			// Not tested here
		}
	}

	@Mocked
	CollectionChangeDelegate<DebuggerModelFactory> factoryChangeListener;
	@Mocked
	CollectionChangeDelegate<DebuggerObjectModel> modelChangeListener;
	@Mocked
	CollectionChangeDelegate<TraceRecorder> recorderChangeListener;

	@Test
	public void testGetModelFactories() throws Exception {
		modelServiceInternal.setModelFactories(List.of(mb.testFactory));
		assertEquals(Set.of(mb.testFactory), modelService.getModelFactories());
	}

	@Test
	public void testListenModelFactoryAdded() throws Exception {
		modelServiceInternal.setModelFactories(List.of());
		modelService.addFactoriesChangedListener(
			new CollectionChangeDelegateWrapper<>(factoryChangeListener));
		modelServiceInternal.setModelFactories(List.of(mb.testFactory));

		new VerificationsInOrder() {
			{
				factoryChangeListener.elementAdded(mb.testFactory);
			}
		};
	}

	/**
	 * If this test fails, then many others probably failed because of a bug in jmockit. It seems to
	 * patch static interface methods to return null, if it needs to mock any instance with the
	 * interface in its type hierarchy.
	 */
	@Test
	public void testJMockitCanary() {
		assertEquals(CollectionChangeListener.class, CollectionChangeListener.of(Integer.class));
	}

	@Test
	public void testListenModelFactoryRemoved() throws Exception {
		modelServiceInternal.setModelFactories(List.of(mb.testFactory));
		// Strong ref
		CollectionChangeDelegateWrapper<DebuggerModelFactory> wrapper =
			new CollectionChangeDelegateWrapper<>(factoryChangeListener);
		modelService.addFactoriesChangedListener(wrapper);
		modelServiceInternal.setModelFactories(List.of());

		new VerificationsInOrder() {
			{
				factoryChangeListener.elementRemoved(mb.testFactory);
			}
		};
	}

	@Test
	public void testGetModels() throws Exception {
		assertEquals(Set.of(), modelService.getModels());
		createTestModel();
		assertEquals(Set.of(mb.testModel), modelService.getModels());
	}

	@Test
	public void testListenModelAdded() throws Exception {
		// Strong ref
		CollectionChangeDelegateWrapper<DebuggerObjectModel> wrapper =
			new CollectionChangeDelegateWrapper<>(modelChangeListener);
		modelService.addModelsChangedListener(wrapper);
		createTestModel();

		new VerificationsInOrder() {
			{
				modelChangeListener.elementAdded(mb.testModel);
			}
		};
	}

	@Test
	public void testListenModelRemoved() throws Exception {
		createTestModel();

		modelService.addModelsChangedListener(
			new CollectionChangeDelegateWrapper<>(modelChangeListener));
		modelService.removeModel(mb.testModel);

		new VerificationsInOrder() {
			{
				modelChangeListener.elementRemoved(mb.testModel);
			}
		};
	}

	@Test
	public void testGetTraceRecorders() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		assertEquals(Set.of(), Set.copyOf(modelService.getTraceRecorders()));
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		assertEquals(Set.of(recorder), Set.copyOf(modelService.getTraceRecorders()));
	}

	@Test
	public void testListenTraceRecorderAdded() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		// Strong ref
		CollectionChangeDelegateWrapper<TraceRecorder> wrapper =
			new CollectionChangeDelegateWrapper<>(recorderChangeListener);
		modelService.addTraceRecordersChangedListener(wrapper);
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		new VerificationsInOrder() {
			{
				recorderChangeListener.elementAdded(recorder);
			}
		};
	}

	@Test
	public void testListenTraceRecorderRemoved() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		// Strong ref
		CollectionChangeDelegateWrapper<TraceRecorder> wrapper =
			new CollectionChangeDelegateWrapper<>(recorderChangeListener);
		modelService.addTraceRecordersChangedListener(wrapper);
		recorder.stopRecording();

		new VerificationsInOrder() {
			{
				recorderChangeListener.elementRemoved(recorder);
			}
		};
	}

	@Test
	public void testStartLocalSession() throws Exception {
		TestLocalDebuggerModelFactory factory = new TestLocalDebuggerModelFactory();
		modelServiceInternal.setModelFactories(List.of(factory));

		CompletableFuture<? extends DebuggerObjectModel> futureSession =
			modelService.startLocalSession();
		TestDebuggerObjectModel model = new TestDebuggerObjectModel();
		assertEquals(Set.of(), modelService.getModels());
		factory.pollBuild().complete(model);
		futureSession.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);

		assertEquals(Set.of(model), modelService.getModels());
	}

	@Test
	public void testRecordThenCloseStopsRecording() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		assertNotNull(recorder);
		waitOn(recorder.init()); // Already initializing, just wait for it to complete

		waitOn(mb.testModel.close());
		waitForPass(() -> {
			assertFalse("Still recording", recorder.isRecording());
		});
	}

	@Test
	public void testRecordAndOpenThenCloseModelAndTraceLeavesNoConsumers() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		modelService.recordTargetAndActivateTrace(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		waitForSwing();

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull("No active trace", trace);

		traceManager.closeTrace(trace);
		waitOn(mb.testModel.close());
		waitForPass(() -> {
			assertEquals(List.of(), trace.getConsumerList());
		});
	}

	@Test
	public void testGetRecorderByTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		assertEquals(recorder, modelService.getRecorder(mb.testProcess1));
	}

	@Test
	public void testGetRecorderByTrace() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		assertEquals(recorder, modelService.getRecorder(recorder.getTrace()));
	}

	@Test
	public void testGetTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		assertEquals(mb.testProcess1, modelService.getTarget(recorder.getTrace()));
	}

	@Test
	public void testGetTrace() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		assertEquals(recorder.getTrace(), modelService.getTrace(mb.testProcess1));
	}

	@Test
	public void testGetTargetThread() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		// The most complicated case, lest I want another dimension in a cross product
		mb.createTestThreadStacksAndFramesHaveRegisterBanks();

		// Recorder uses async executor, so wait for thread to appear....
		waitFor(() -> recorder.getTrace()
				.getThreadManager()
				.getThreadsByPath("Processes[1].Threads[1]")
				.size() == 1);

		TraceThread traceThread = Unique.assertOne(
			recorder.getTrace().getThreadManager().getThreadsByPath("Processes[1].Threads[1]"));
		/**
		 * There's a brief period where the trace thread exists, but it hasn't been entered into the
		 * recorder's internal map, yet. So, we have to wait.
		 */
		waitForPass(() -> {
			assertEquals(mb.testThread1, modelService.getTargetThread(traceThread));
		});
	}

	protected void doTestGetTraceThread(Runnable preRec, Runnable postRec) throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		preRec.run();

		modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		postRec.run();

		waitForPass(() -> {
			TraceThread traceThread = modelService.getTraceThread(mb.testThread1);
			assertNotNull("testThread1 is mapped to null", traceThread);
			assertEquals("Processes[1].Threads[1]", traceThread.getPath());
		});
	}

	@Test
	public void testGetTraceThreadWhereBankInThreadPreRecord() throws Exception {
		doTestGetTraceThread(mb::createTestThreadRegisterBanks, this::nop);
	}

	@Test
	public void testGetTraceThreadWhereBankInThreadPostRecord() throws Exception {
		doTestGetTraceThread(this::nop, mb::createTestThreadRegisterBanks);
	}

	@Test
	public void testGetTraceThreadWhereBankInStackPreRecord() throws Exception {
		doTestGetTraceThread(mb::createTestThreadStacksAndFramesAreRegisterBanks, this::nop);
	}

	@Test
	public void testGetTraceThreadWhereBankInStackPostRecord() throws Exception {
		doTestGetTraceThread(this::nop, mb::createTestThreadStacksAndFramesAreRegisterBanks);
	}

	@Test
	public void testGetTraceThreadWhereBankInFramePreRecord() throws Exception {
		doTestGetTraceThread(mb::createTestThreadStacksAndFramesHaveRegisterBanks, this::nop);
	}

	@Test
	public void testGetTraceThreadWhereBankInFramePostRecord() throws Exception {
		doTestGetTraceThread(this::nop, mb::createTestThreadStacksAndFramesHaveRegisterBanks);
	}

	@Test
	public void testGetTraceThreadWithTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));

		// The most complicated case, lest I want another dimension in a cross product
		mb.createTestThreadStacksAndFramesHaveRegisterBanks();

		waitForPass(() -> {
			TraceThread traceThread = modelService.getTraceThread(mb.testProcess1, mb.testThread1);
			assertNotNull(traceThread);
			assertEquals("Processes[1].Threads[1]", traceThread.getPath());
		});
	}

	@Test
	public void testTargetFocus() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		// NOTE: getTargetFocus assumes the target is being recorded
		modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		modelService.recordTarget(mb.testProcess3,
			new TestDebuggerTargetTraceMapper(mb.testProcess3));

		assertNull(modelService.getTargetFocus(mb.testProcess1));
		assertNull(modelService.getTargetFocus(mb.testProcess3));

		waitOn(mb.testModel.requestFocus(mb.testThread1));
		assertEquals(mb.testThread1, modelService.getTargetFocus(mb.testProcess1));
		assertNull(modelService.getTargetFocus(mb.testProcess3));

		waitOn(mb.testModel.requestFocus(mb.testThread2));
		assertEquals(mb.testThread2, modelService.getTargetFocus(mb.testProcess1));
		assertNull(modelService.getTargetFocus(mb.testProcess3));

		waitOn(mb.testModel.requestFocus(mb.testThread3));
		assertEquals(mb.testThread2, modelService.getTargetFocus(mb.testProcess1));
		assertEquals(mb.testThread3, modelService.getTargetFocus(mb.testProcess3));

		waitOn(mb.testModel.requestFocus(mb.testThread4));
		assertEquals(mb.testThread2, modelService.getTargetFocus(mb.testProcess1));
		assertEquals(mb.testThread4, modelService.getTargetFocus(mb.testProcess3));
	}

	@Test
	public void testFocusGeneratesEvents() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		// NOTE: These events are generated whether or not associated with a recorder
		AsyncPairingQueue<ModelObjectFocusedPluginEvent> focusEvents = new AsyncPairingQueue<>();
		tool.addListenerForAllPluginEvents(event -> {
			if (event instanceof ModelObjectFocusedPluginEvent) {
				ModelObjectFocusedPluginEvent evt = (ModelObjectFocusedPluginEvent) event;
				focusEvents.give().complete(evt);
			}
		});

		mb.testModel.requestFocus(mb.testThread1);
		mb.testModel.requestFocus(mb.testThread2);
		ModelObjectFocusedPluginEvent evt1 =
			focusEvents.take().get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		ModelObjectFocusedPluginEvent evt2 =
			focusEvents.take().get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		assertEquals(mb.testThread1, evt1.getFocusRef());
		assertEquals(mb.testThread2, evt2.getFocusRef());
	}

	@Test
	public void testCurrentModelNullAfterClose() throws Throwable {
		createTestModel();

		modelService.activateModel(mb.testModel);
		assertEquals(mb.testModel, modelService.getCurrentModel());

		waitOn(mb.testModel.close());
		assertNull(modelService.getCurrentModel());
	}
}
