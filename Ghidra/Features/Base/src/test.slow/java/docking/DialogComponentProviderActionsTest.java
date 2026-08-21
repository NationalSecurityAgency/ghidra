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
package docking;

import static org.junit.Assert.*;

import java.awt.Component;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.actions.KeyBindingUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.*;
import ghidra.util.Msg;
import ghidra.util.SpyErrorLogger;

public class DialogComponentProviderActionsTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private DialogComponentProvider provider;
	private SpyErrorLogger spyLogger = new SpyErrorLogger();

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.launchDefaultTool();
		env.open(new ClassicSampleX86ProgramBuilder().getProgram());

		provider = new TestDialogComponentProvider();

		Msg.setErrorLogger(spyLogger);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testKeyBinding() {
		//
		// Create an action for the dialog that has a keybinding.  Ensure that the action can be 
		// triggered while the dialog is showing.
		//
		SpyAction spyAction = new SpyAction();

		String ksText = "Control Y";
		setKeyBinding(spyAction, ksText);
		addAction(spyAction);

		// the action should not work if the dialog is not showing
		triggerKey(ksText);
		assertFalse(spyAction.hasBeenCalled());

		showDialogWithoutBlocking(tool, provider);
		waitForDialogComponent(provider.getTitle());

		triggerKey(ksText);
		assertTrue(spyAction.hasBeenCalled());
		close(provider);
	}

	@Test
	public void testKeyBinding_SameAsGlobalKeyBinding() {
		//
		// Create an action for the dialog that has a keybinding.  Use a key binding that is the 
		// same as a global tool action so that both could be triggered.  Verify that only the 
		// dialog's action is executed while the dialog is showing.
		//
		SpyAction spyAction = new SpyAction();

		String ksText = "G";
		setKeyBinding(spyAction, ksText);
		addAction(spyAction);

		// verify the Go To dialog appears (and not Multiple Key Binding Dialog)
		triggerKey(ksText);
		DialogComponentProvider dialog = waitForDialogComponent("Go To ...");
		close(dialog);

		showDialogWithoutBlocking(tool, provider);
		waitForDialogComponent(provider.getTitle());

		triggerKey(ksText);
		assertTrue(spyAction.hasBeenCalled());
		close(provider);
	}

	private void addAction(DockingAction action) {
		runSwing(() -> provider.addAction(action));
	}

	private void setKeyBinding(DockingAction action, String ksText) {
		runSwing(() -> {
			action.setKeyBindingData(new KeyBindingData(ksText));
		});
	}

	private void triggerKey(String ksText) {
		Component component = provider.getComponent();
		if (!provider.isShowing()) {
			CodeBrowserPlugin cbp = env.getPlugin(CodeBrowserPlugin.class);
			CodeViewerProvider cvp = cbp.getProvider();
			component = cvp.getComponent();
		}
		KeyStroke ks = KeyBindingUtils.parseKeyStroke(ksText);
		triggerKey(component, ks);
		waitForSwing();
	}

	private class SpyAction extends DockingAction {

		private volatile boolean hasBeenCalled;

		public SpyAction() {
			super("Some Dialog Action", "Some Owner");
		}

		@Override
		public void actionPerformed(ActionContext context) {
			hasBeenCalled = true;
		}

		boolean hasBeenCalled() {
			return hasBeenCalled;
		}
	}

	private class TestDialogComponentProvider extends DialogComponentProvider {

		private JComponent component = new JButton("Hey!");

		protected TestDialogComponentProvider() {
			super("Test Dialog");
		}

		@Override
		public JComponent getComponent() {
			return component;
		}
	}
}
