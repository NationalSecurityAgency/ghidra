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
package ghidra.app.plugin.core.debug.gui.objects;

import static ghidra.lifecycle.Unfinished.TODO;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.objects.components.*;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceProxyPlugin;
import ghidra.dbg.model.*;
import ghidra.dbg.target.*;
import ghidra.dbg.testutil.DebuggerModelTestUtils;
import ghidra.util.Swing;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerObjectsPluginScreenShots extends GhidraScreenShotGenerator
		implements DebuggerModelTestUtils {

	TestDebuggerModelBuilder mb = new TestDebuggerModelBuilder();
	DebuggerModelServiceProxyPlugin modelService;
	DebuggerObjectsPlugin objectsPlugin;
	DebuggerObjectsProvider objectsProvider;

	@Before
	public void setUpMine() throws Exception {
		modelService = addPlugin(tool, DebuggerModelServiceProxyPlugin.class);
		objectsPlugin = addPlugin(tool, DebuggerObjectsPlugin.class);
		objectsProvider = waitForComponentProvider(DebuggerObjectsProvider.class);
	}

	// A cheap way to control what buttons are enabled
	static class ActionyTestTargetObject
			extends DefaultTestTargetObject<TestTargetObject, TestTargetObject>
			implements TargetInterpreter, TargetResumable, TargetSteppable, TargetLauncher,
			TargetAttacher, TargetAttachable {

		public ActionyTestTargetObject(TestTargetObject parent, String name, String typeHint) {
			super(parent, name, typeHint);
		}

		@Override
		public CompletableFuture<Void> launch(Map<String, ?> args) {
			return TODO();
		}

		@Override
		public CompletableFuture<Void> attach(TargetAttachable attachable) {
			return TODO();
		}

		@Override
		public CompletableFuture<Void> attach(long id) {
			return TODO();
		}

		@Override
		public CompletableFuture<Void> step(TargetStepKind kind) {
			return TODO();
		}

		@Override
		public CompletableFuture<Void> resume() {
			return TODO();
		}

		@Override
		public CompletableFuture<Void> execute(String cmd) {
			return TODO();
		}

		@Override
		public CompletableFuture<String> executeCapture(String cmd) {
			return TODO();
		}
	}

	/**
	 * NOTE: The icon selection looks like it relies of "duck typing", which is probably not the
	 * Right Way. I would have expected it to consume the type hint. Eh. Anyway, let's take a
	 * screenshot, shall we?
	 * 
	 * <p>
	 * Depending on the text in the help, we could probably do something more generic, or maybe even
	 * just use the test model as is. Don't know how much illustration is needed in the screenshot.
	 */
	@Test
	public void testCaptureDebuggerObjectsPlugin() throws Throwable {
		mb.createTestModel("Debugger");

		DefaultTestTargetObject<?, ?> available =
			new DefaultTestTargetObject<>(mb.testModel.session, "Available", "");
		DefaultTestTargetObject<TestTargetObject, ?> sessions =
			new DefaultTestTargetObject<>(mb.testModel.session, "Sessions", "");

		DefaultTestTargetObject<?, ?> session0 =
			new DefaultTestTargetObject<>(sessions, "[0x0]", "");

		DefaultTestTargetObject<?, ?> sAttributes =
			new DefaultTestTargetObject<>(session0, "Attributes", "");
		DefaultTestTargetObject<?, ?> sDevices =
			new DefaultTestTargetObject<>(session0, "Devices", "");
		DefaultTestTargetObject<TestTargetObject, ?> sProcesses =
			new DefaultTestTargetObject<>(session0, "Processes", "");

		DefaultTestTargetObject<?, ?> process1a12 =
			new DefaultTestTargetObject<>(sProcesses, "[0x1a12]", "");

		DefaultTestTargetObject<?, ?> pDebug =
			new DefaultTestTargetObject<>(process1a12, "Debug", "");
		DefaultTestTargetObject<?, ?> pDevices =
			new DefaultTestTargetObject<>(process1a12, "Devices", "");
		DefaultTestTargetObject<?, ?> pEnvironment =
			new DefaultTestTargetObject<>(process1a12, "Environment", "");
		DefaultTestTargetObject<?, ?> pIo = new DefaultTestTargetObject<>(process1a12, "Io", "");
		DefaultTestTargetObject<?, ?> pMemory =
			new DefaultTestTargetObject<>(process1a12, "Memory", "");
		DefaultTestTargetObject<?, ?> pModules =
			new DefaultTestTargetObject<>(process1a12, "Modules", "");
		DefaultTestTargetObject<TestTargetObject, ?> pThreads =
			new DefaultTestTargetObject<>(process1a12, "Threads", "");

		DefaultTestTargetObject<?, ?> thread1a34 =
			new ActionyTestTargetObject(pThreads, "[0x1a34]", "");

		mb.testModel.session.setAttributes(List.of(),
			Map.of(TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME, thread1a34, // Get arrow icon on thread
				TargetObject.DISPLAY_ATTRIBUTE_NAME, "Debugger"),
			"TestOverride");

		DefaultTestTargetObject<?, ?> tEnvironment =
			new DefaultTestTargetObject<>(thread1a34, "Environment", "");

		DefaultTestTargetObject<?, ?> teEnvBlock =
			new DefaultTestTargetObject<>(tEnvironment, "EnvironmentBlock", "");

		DefaultTestTargetObject<?, ?> activationContextStackPointer =
			new DefaultTestTargetObject<>(teEnvBlock, "ActivationContextStackPointer", "");
		activationContextStackPointer
				.setAttributes(List.of(),
					Map.of(TargetObject.DISPLAY_ATTRIBUTE_NAME,
						"ActivationContextStackPointer : 789abc", "_modified", true),
					"Initialized");
		DefaultTestTargetObject<?, ?> activeFrame =
			new DefaultTestTargetObject<>(teEnvBlock, "ActiveFrame", "");
		activeFrame.setAttributes(List.of(),
			Map.of(TargetObject.DISPLAY_ATTRIBUTE_NAME, "ActiveFrame : 0", "_modified", true),
			"Initialized");
		DefaultTestTargetObject<?, ?> bogusFocus =
			new DefaultTestTargetObject<>(teEnvBlock, "BOGUS FOCUS", "");
		teEnvBlock.setAttributes(List.of(activationContextStackPointer, activeFrame, bogusFocus),
			Map.of("_kind", "OBJECT_TARGET_OBJECT"), // Makes it magenta
			"Initialized");

		tEnvironment.setAttributes(List.of(teEnvBlock), Map.of(), "Initialized");

		thread1a34.setAttributes(List.of(tEnvironment),
			Map.of(TargetObject.DISPLAY_ATTRIBUTE_NAME, "0x1a34"), "Initialized");

		pThreads.setElements(List.of(thread1a34), Map.of(), "Initialized");

		process1a12.setAttributes(
			List.of(pDebug, pDevices, pEnvironment, pIo, pMemory, pModules, pThreads),
			Map.of(TargetObject.DISPLAY_ATTRIBUTE_NAME, "0x1a12", "Handle", "321", "Id", "1a12",
				"Name", "winmine.exe"),
			"Initialized");

		sProcesses.setElements(List.of(process1a12), Map.of(), "Initialized");

		session0.setAttributes(List.of(sAttributes, sDevices, sProcesses),
			Map.of(TargetObject.DISPLAY_ATTRIBUTE_NAME, "0x0", "Id", 0), "Initialized");

		sessions.setElements(List.of(session0), Map.of(), "Initialized");

		mb.testModel.session.changeAttributes(List.of(), List.of(available, sessions), Map.of(),
			"Initialized");

		Swing.runNow(() -> {
			modelService.addModel(mb.testModel);
			modelService.activateModel(mb.testModel);
		});
		waitForSwing();

		mb.testModel.session.requestFocus(bogusFocus);
		waitForSwing();
		mb.testModel.session.requestFocus(mb.testModel.session);
		waitForSwing();
		mb.testModel.session.requestFocus(thread1a34);
		waitForSwing();
		teEnvBlock.changeAttributes(List.of("BOGUS FOCUS"), List.of(), Map.of(), "Clean");
		waitForSwing();

		captureIsolatedProvider(objectsProvider, 600, 600);
	}

	@Test
	public void testCaptureDebuggerMethodInvocationDialog_ForLaunch() throws Throwable {
		mb.createTestModel();
		mb.createTestProcessesAndThreads();

		modelService.addModel(mb.testModel);
		modelService.activateModel(mb.testModel);
		waitForSwing();

		waitOn(mb.testModel.session.requestFocus(mb.testModel.session.mimickJavaLauncher));
		waitForSwing();

		performAction(objectsProvider.actionLaunch, false);
		DebuggerMethodInvocationDialog dialog =
			waitForDialogComponent(DebuggerMethodInvocationDialog.class);
		captureDialog(dialog);
	}

	@Test
	public void testCaptureDebuggerBreakpointDialog() throws Throwable {
		mb.createTestModel();
		mb.createTestProcessesAndThreads();

		modelService.addModel(mb.testModel);
		modelService.activateModel(mb.testModel);
		waitForSwing();

		waitOn(mb.testModel.session.requestFocus(mb.testProcess1.breaks));
		waitForSwing();

		performAction(objectsProvider.actionAddBreakpoint, false);
		DebuggerBreakpointDialog dialog = waitForDialogComponent(DebuggerBreakpointDialog.class);
		DebuggerObjectsAccessHelper.setDebuggerBreakpointDialogExpression(dialog, "get_env");
		captureDialog(dialog);
	}
}
