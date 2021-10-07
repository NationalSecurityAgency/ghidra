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

import java.awt.Component;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.swing.JLabel;
import javax.swing.JTextField;

import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.debug.event.ModelObjectFocusedPluginEvent;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractConnectAction;
import ghidra.app.plugin.core.debug.service.model.DebuggerConnectDialog.FactoryEntry;
import ghidra.app.plugin.core.debug.service.model.TestDebuggerProgramLaunchOpinion.TestDebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncPairingQueue;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.model.TestDebuggerModelFactory;
import ghidra.dbg.model.TestDebuggerObjectModel;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.testutil.DebuggerModelTestUtils;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Swing;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.CollectionChangeListener;
import mockit.Mocked;
import mockit.VerificationsInOrder;

/**
 * TODO: Cover the error cases, and cases where {@code null} is expected
 * 
 * <p>
 * TODO: Cover cases where multiple recorders are present
 */
public class DebuggerModelServiceTest extends AbstractGhidraHeadedDebuggerGUITest
		implements DebuggerModelTestUtils {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

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

	static class CollectionChangeDelegateWrapper<E> implements CollectionChangeListener<E> {
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
	public void testGetProgramLaunchOffers() throws Exception {
		createAndOpenProgramWithExePath("/my/fun/path");
		TestDebuggerModelFactory factory = new TestDebuggerModelFactory();
		modelServiceInternal.setModelFactories(List.of(factory));
		List<DebuggerProgramLaunchOffer> offers =
			modelService.getProgramLaunchOffers(program).collect(Collectors.toList());
		DebuggerProgramLaunchOffer offer = Unique.assertOne(offers);
		assertEquals(TestDebuggerProgramLaunchOffer.class, offer.getClass());
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
		Trace trace = recorder.getTrace();
		recorder.stopRecording();
		waitForDomainObject(trace);

		new VerificationsInOrder() {
			{
				recorderChangeListener.elementRemoved(recorder);
			}
		};
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
		waitForPass(
			() -> assertEquals(mb.testThread1, modelService.getTargetFocus(mb.testProcess1)));
		waitForPass(() -> assertNull(modelService.getTargetFocus(mb.testProcess3)));

		waitOn(mb.testModel.requestFocus(mb.testThread2));
		waitForPass(
			() -> assertEquals(mb.testThread2, modelService.getTargetFocus(mb.testProcess1)));
		waitForPass(() -> assertNull(modelService.getTargetFocus(mb.testProcess3)));

		waitOn(mb.testModel.requestFocus(mb.testThread3));
		waitForPass(
			() -> assertEquals(mb.testThread2, modelService.getTargetFocus(mb.testProcess1)));
		waitForPass(
			() -> assertEquals(mb.testThread3, modelService.getTargetFocus(mb.testProcess3)));

		waitOn(mb.testModel.requestFocus(mb.testThread4));
		waitForPass(
			() -> assertEquals(mb.testThread2, modelService.getTargetFocus(mb.testProcess1)));
		waitForPass(
			() -> assertEquals(mb.testThread4, modelService.getTargetFocus(mb.testProcess3)));
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
		assertEquals(mb.testThread1, evt1.getFocus());
		assertEquals(mb.testThread2, evt2.getFocus());
	}

	@Test
	public void testCurrentModelNullAfterClose() throws Throwable {
		createTestModel();

		modelService.activateModel(mb.testModel);
		assertEquals(mb.testModel, modelService.getCurrentModel());

		waitOn(mb.testModel.close());
		assertNull(modelService.getCurrentModel());
	}

	@Test
	public void testConnectDialogPopulates() {
		modelServiceInternal.setModelFactories(List.of(mb.testFactory));
		waitForSwing();

		Swing.runLater(() -> modelService.showConnectDialog());
		DebuggerConnectDialog dialog = waitForDialogComponent(DebuggerConnectDialog.class);

		FactoryEntry fe = (FactoryEntry) dialog.dropdownModel.getSelectedItem();
		assertEquals(mb.testFactory, fe.factory);

		assertEquals(TestDebuggerModelFactory.FAKE_DETAILS_HTML, dialog.description.getText());

		Component[] components = dialog.pairPanel.getComponents();

		assertTrue(components[0] instanceof JLabel);
		JLabel label = (JLabel) components[0];
		assertEquals(TestDebuggerModelFactory.FAKE_OPTION_NAME, label.getText());

		assertTrue(components[1] instanceof JTextField);
		JTextField field = (JTextField) components[1];
		assertEquals(TestDebuggerModelFactory.FAKE_DEFAULT, field.getText());

		pressButtonByText(dialog, "Cancel", true);
	}

	@Test
	public void testConnectDialogConnectsAndRegistersModelWithService() throws Throwable {
		modelServiceInternal.setModelFactories(List.of(mb.testFactory));

		CompletableFuture<DebuggerObjectModel> futureModel = new CompletableFuture<>();
		CollectionChangeListener<DebuggerObjectModel> listener =
			new CollectionChangeListener<DebuggerObjectModel>() {
				@Override
				public void elementAdded(DebuggerObjectModel element) {
					futureModel.complete(element);
				}

				@Override
				public void elementModified(DebuggerObjectModel element) {
					// Don't care
				}

				@Override
				public void elementRemoved(DebuggerObjectModel element) {
					fail();
				}
			};
		modelService.addModelsChangedListener(listener);
		Swing.runLater(() -> modelService.showConnectDialog());

		DebuggerConnectDialog connectDialog = waitForDialogComponent(DebuggerConnectDialog.class);

		FactoryEntry fe = (FactoryEntry) connectDialog.dropdownModel.getSelectedItem();
		assertEquals(mb.testFactory, fe.factory);

		pressButtonByText(connectDialog, AbstractConnectAction.NAME, true);
		// NOTE: testModel is null. Don't use #createTestModel(), which adds to service
		TestDebuggerObjectModel model = new TestDebuggerObjectModel();
		mb.testFactory.pollBuild().complete(model);
		assertEquals(model, waitOn(futureModel));
	}

	@Test
	public void testRecordBestOfferRecognized() throws Exception {
		createTestModel();
		mb.testModel.session.environment.changeAttributes(List.of(),
			Map.of(TargetEnvironment.ARCH_ATTRIBUTE_NAME, TestKnownArchDebuggerMappingOpinion.ARCH),
			"Testing");
		mb.createTestProcessesAndThreads();
		// NB. Model service does not "auto-record". Objects provider does that.

		modelService.recordTargetBestOffer(mb.testProcess1);

		assertEquals(1, modelService.getTraceRecorders().size());
	}

	@Test(expected = NoSuchElementException.class)
	public void testRecordBestOfferUnrecognized() throws Exception {
		createTestModel();
		mb.testModel.session.environment.changeAttributes(List.of(),
			Map.of(TargetEnvironment.ARCH_ATTRIBUTE_NAME, "test-bogus-arch"),
			"Testing");
		mb.createTestProcessesAndThreads();

		modelService.recordTargetBestOffer(mb.testProcess1);
	}

	@Test
	public void testRecordPromptOffersRecognized() throws Exception {
		createTestModel();
		mb.testModel.session.environment.changeAttributes(List.of(),
			Map.of(TargetEnvironment.ARCH_ATTRIBUTE_NAME, TestKnownArchDebuggerMappingOpinion.ARCH),
			"Testing");
		mb.createTestProcessesAndThreads();

		runSwingLater(() -> modelService.recordTargetPromptOffers(mb.testProcess1));
		DebuggerSelectMappingOfferDialog dialog =
			waitForDialogComponent(DebuggerSelectMappingOfferDialog.class);
		dialog.okCallback();

		waitForPass(() -> assertEquals(1, modelService.getTraceRecorders().size()));
	}

	@Test
	public void testRecordPromptOffersUnrecognized() throws Exception {
		createTestModel();
		mb.testModel.session.environment.changeAttributes(List.of(),
			Map.of(TargetEnvironment.ARCH_ATTRIBUTE_NAME, "test-bogus-arch"),
			"Testing");
		mb.createTestProcessesAndThreads();

		runSwingLater(() -> modelService.recordTargetPromptOffers(mb.testProcess1));
		DebuggerSelectMappingOfferDialog dialog =
			waitForDialogComponent(DebuggerSelectMappingOfferDialog.class);

		assertTrue(dialog.getDisplayedOffers().isEmpty());

		runSwing(() -> dialog.setFilterRecommended(false));
		waitForPass(() -> assertFalse(dialog.getDisplayedOffers().isEmpty()));
		// TODO: setFilterRecommended's call to selectPreferred comes to early.
		if (dialog.getSelectedOffer() == null) {
			dialog.setSelectedOffer(dialog.getDisplayedOffers().get(0));
		}

		// Do I care which language is actually selected?
		dialog.okCallback();

		waitForPass(() -> assertEquals(1, modelService.getTraceRecorders().size()));
	}
}
