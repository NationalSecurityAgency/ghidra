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
import org.junit.experimental.categories.Category;

import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.event.ModelObjectFocusedPluginEvent;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractConnectAction;
import ghidra.app.plugin.core.debug.service.model.DebuggerConnectDialog.FactoryEntry;
import ghidra.app.plugin.core.debug.service.model.TestDebuggerProgramLaunchOpinion.TestDebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.app.services.ActionSource;
import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncPairingQueue;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.model.TestDebuggerModelFactory;
import ghidra.dbg.model.TestDebuggerObjectModel;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Swing;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.CollectionChangeListener;

/**
 * TODO: Cover the error cases, and cases where {@code null} is expected
 *
 * <p>
 * TODO: Cover cases where multiple recorders are present
 */
@Category(NightlyCategory.class)
public class DebuggerModelServiceTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected static final long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	protected static class NoDuplicatesTrackingChangeListener<E>
			implements CollectionChangeListener<E> {
		Set<E> current = new HashSet<>();

		protected String formatObj(E e) {
			return String.format("%s@%08x", e.getClass().getSimpleName(),
				System.identityHashCode(e));
		}

		@Override
		public synchronized void elementAdded(E element) {
			assertTrue(current.add(element));
		}

		@Override
		public synchronized void elementModified(E element) {
			assertTrue(current.contains(element));
		}

		@Override
		public synchronized void elementRemoved(E element) {
			assertTrue(current.remove(element));
		}

		public synchronized void sync(Collection<E> current) {
			this.current.clear();
			this.current.addAll(current);
		}

		public synchronized void assertAgrees(Collection<E> expected) {
			assertEquals(Set.copyOf(expected), current);
		}
	}

	NoDuplicatesTrackingChangeListener<DebuggerModelFactory> factoryChangeListener =
		new NoDuplicatesTrackingChangeListener<>();
	NoDuplicatesTrackingChangeListener<DebuggerObjectModel> modelChangeListener =
		new NoDuplicatesTrackingChangeListener<>();
	NoDuplicatesTrackingChangeListener<TraceRecorder> recorderChangeListener =
		new NoDuplicatesTrackingChangeListener<>();

	@Test
	public void testGetModelFactories() throws Exception {
		modelServiceInternal.setModelFactories(List.of(mb.testFactory));
		assertEquals(Set.of(mb.testFactory), modelService.getModelFactories());
	}

	@Test
	public void testListenModelFactoryAdded() throws Exception {
		modelServiceInternal.setModelFactories(List.of());
		modelService.addFactoriesChangedListener(factoryChangeListener);
		modelServiceInternal.setModelFactories(List.of(mb.testFactory));

		factoryChangeListener.assertAgrees(modelService.getModelFactories());
	}

	@Test
	public void testListenModelFactoryRemoved() throws Exception {
		modelServiceInternal.setModelFactories(List.of(mb.testFactory));
		modelService.addFactoriesChangedListener(factoryChangeListener);
		factoryChangeListener.sync(modelService.getModelFactories());
		modelServiceInternal.setModelFactories(List.of());

		factoryChangeListener.assertAgrees(modelService.getModelFactories());
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
		modelService.addModelsChangedListener(modelChangeListener);
		createTestModel();

		modelChangeListener.assertAgrees(modelService.getModels());
	}

	@Test
	public void testListenModelRemoved() throws Exception {
		createTestModel();

		modelService.addModelsChangedListener(modelChangeListener);
		modelChangeListener.sync(modelService.getModels());
		modelService.removeModel(mb.testModel);

		modelChangeListener.assertAgrees(modelService.getModels());
	}

	@Test
	public void testGetTraceRecorders() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		assertEquals(Set.of(), Set.copyOf(modelService.getTraceRecorders()));
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);

		assertEquals(Set.of(recorder), Set.copyOf(modelService.getTraceRecorders()));
	}

	@Test
	public void testListenTraceRecorderAdded() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		modelService.addTraceRecordersChangedListener(recorderChangeListener);
		modelService.recordTarget(mb.testProcess1, createTargetTraceMapper(mb.testProcess1),
			ActionSource.AUTOMATIC);

		recorderChangeListener.assertAgrees(modelService.getTraceRecorders());
	}

	@Test
	public void testListenTraceRecorderRemoved() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		modelService.addTraceRecordersChangedListener(recorderChangeListener);
		recorderChangeListener.sync(modelService.getTraceRecorders());
		Trace trace = recorder.getTrace();
		recorder.stopRecording();
		waitForDomainObject(trace);

		recorderChangeListener.assertAgrees(modelService.getTraceRecorders());
	}

	@Test
	public void testRecordThenCloseStopsRecording() throws Throwable {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
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
			createTargetTraceMapper(mb.testProcess1));
		waitForSwing();

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull("No active trace", trace);

		traceManager.closeTrace(trace);
		waitOn(mb.testModel.close());
		waitForPass(() -> {
			assertEquals(List.of(tb), trace.getConsumerList());
		});
	}

	@Test
	public void testGetRecorderByTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);

		assertEquals(recorder, modelService.getRecorder(mb.testProcess1));
	}

	@Test
	public void testGetRecorderByTrace() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);

		assertEquals(recorder, modelService.getRecorder(recorder.getTrace()));
	}

	@Test
	public void testGetTarget() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);

		assertEquals(mb.testProcess1, modelService.getTarget(recorder.getTrace()));
	}

	@Test
	public void testGetTrace() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);

		assertEquals(recorder.getTrace(), modelService.getTrace(mb.testProcess1));
	}

	@Test
	public void testGetTargetThread() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);

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

		modelService.recordTarget(mb.testProcess1, createTargetTraceMapper(mb.testProcess1),
			ActionSource.AUTOMATIC);

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

		modelService.recordTarget(mb.testProcess1, createTargetTraceMapper(mb.testProcess1),
			ActionSource.AUTOMATIC);

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
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		modelService.recordTarget(mb.testProcess3,
			createTargetTraceMapper(mb.testProcess3), ActionSource.AUTOMATIC);

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

		// Ensure the model is initialized before we close it
		waitOn(mb.testModel.fetchModelRoot());

		modelService.activateModel(mb.testModel);
		assertEquals(mb.testModel, modelService.getCurrentModel());

		waitOn(mb.testModel.close());
		assertNull(modelService.getCurrentModel());
	}

	@Test
	public void testCurrentModelNullAfterCloseNoWait() throws Throwable {
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
			Map.of(TargetEnvironment.ARCH_ATTRIBUTE_NAME, "test-bogus-arch"), "Testing");
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
			Map.of(TargetEnvironment.ARCH_ATTRIBUTE_NAME, "test-bogus-arch"), "Testing");
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
