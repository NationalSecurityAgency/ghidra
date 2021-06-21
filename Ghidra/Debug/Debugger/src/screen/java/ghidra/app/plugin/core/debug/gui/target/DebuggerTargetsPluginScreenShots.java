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
package ghidra.app.plugin.core.debug.gui.target;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.service.model.*;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import ghidra.program.model.address.AddressFactory;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerTargetsPluginScreenShots extends GhidraScreenShotGenerator {

	@FactoryDescription(
		brief = "Demo Debugger",
		htmlDetails = "A connection for demonstration purposes")
	protected static class ScreenShotDebuggerModelFactory implements DebuggerModelFactory {

		private void nop() {
		}

		@FactoryOption("Remote")
		public final Property<Boolean> remoteOption = Property.fromAccessors(Boolean.class,
			() -> true, v -> nop());
		@FactoryOption("Host")
		public final Property<String> hostOption = Property.fromAccessors(String.class,
			() -> "localhost", v -> nop());
		@FactoryOption("Port")
		public final Property<Integer> portOption = Property.fromAccessors(Integer.class,
			() -> 12345, v -> nop());

		@Override
		public CompletableFuture<? extends DebuggerObjectModel> build() {
			throw new AssertionError();
		}
	}

	protected static class ScreenShotDebuggerObjectModel extends AbstractDebuggerObjectModel {
		final DefaultTargetModelRoot root = new DefaultTargetModelRoot(this, "Session");
		final String display;

		public ScreenShotDebuggerObjectModel(String display) {
			this.display = display;
			addModelRoot(root);
		}

		@Override
		public String getBrief() {
			return display;
		}

		@Override
		public CompletableFuture<? extends TargetObject> fetchModelRoot() {
			return CompletableFuture.completedFuture(root);
		}

		@Override
		public AddressFactory getAddressFactory() {
			throw new AssertionError();
		}
	}

	DebuggerModelServiceInternal modelService;
	DebuggerTargetsPlugin targetsPlugin;
	DebuggerTargetsProvider targetsProvider;

	@Before
	public void setUpMine() throws Throwable {
		modelService = addPlugin(tool, DebuggerModelServiceProxyPlugin.class);
		targetsPlugin = addPlugin(tool, DebuggerTargetsPlugin.class);
		targetsProvider = waitForComponentProvider(DebuggerTargetsProvider.class);
	}

	@Test
	public void testCaptureDebuggerTargetsPlugin() throws Throwable {
		modelService.addModel(
			new ScreenShotDebuggerObjectModel("DEMO@1234abcd localhost:12345"));
		modelService.addModel(
			new ScreenShotDebuggerObjectModel("DEMO@4321fedc debug-demo:12345"));

		captureIsolatedProvider(targetsProvider, 400, 300);
	}

	@Test
	public void testCaptureDebuggerConnectDialog() throws Throwable {
		modelService.setModelFactories(List.of(new ScreenShotDebuggerModelFactory()));
		performAction(targetsProvider.actionConnect, false);

		captureDialog(DebuggerConnectDialog.class);
	}
}
