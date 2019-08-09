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
package ghidra.app.plugin.core.navigation;

import static org.junit.Assert.*;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import org.junit.Before;
import org.junit.Test;

import docking.*;
import docking.action.DockingActionIf;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.datastruct.WeakSet;

public class ProviderNavigationPluginTest extends AbstractProgramBasedTest {

	private ProviderNavigationPlugin plugin;
	private DockingActionIf previousProviderAction;

	private SpyProviderActivator spyProviderActivator = new SpyProviderActivator();
	private Set<DockingContextListener> testContextListeners;

	@Before
	public void setUp() throws Exception {
		initialize();

		plugin = env.getPlugin(ProviderNavigationPlugin.class);
		previousProviderAction =
			getAction(tool, ProviderNavigationPlugin.GO_TO_LAST_ACTIVE_COMPONENT_ACTION_NAME);

		fakeOutContextNotification();
	}

	@SuppressWarnings("unchecked")
	private void fakeOutContextNotification() {
		// 
		// This is the mechanism the tool uses for notifying clients of Component Provider 
		// activation.  This activation is focus-sensitive, which makes it unreliable for testing.
		// Thus, replace this mechanism with one that we can control.
		//
		DockingWindowManager windowManager = tool.getWindowManager();
		testContextListeners = new HashSet<>();
		WeakSet<DockingContextListener> contextListeners =
			(WeakSet<DockingContextListener>) getInstanceField("contextListeners", windowManager);
		testContextListeners.addAll(contextListeners.values());
		contextListeners.clear();

		//
		// Now, install a spy that allows us to know when our action under test triggers and 
		// with which state it does so.
		//
		plugin.setProviderActivator(spyProviderActivator);

	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory(".text", "0x1001000", 0x6600);
		return builder.getProgram();
	}

	@Test
	public void testGoToLastActiveComponent() {

		clearPluginState();
		assertPreviousProviderActionNotEnabled();

		ComponentProvider bookmarks = activateProvider("Bookmarks");
		assertPreviousProviderActionNotEnabled(); // first provider; nothing to go back to

		ComponentProvider dataTypes = activateProvider("DataTypes Provider");
		assertPreviousProviderActionEnabled();

		// active provider : 'data types'; previous: 'bookmarks'
		performPreviousProviderAction();
		assertActivated(bookmarks);

		// active provider : 'bookmarks'; previous: 'data types'
		performPreviousProviderAction();
		assertActivated(dataTypes);

		activateProvider("Symbol Table");

		// active provider : 'symbol table'; previous: 'data types'
		performPreviousProviderAction();
		assertActivated(dataTypes);
	}

	private void clearPluginState() {
		waitForSwing();
		runSwing(() -> plugin.resetTrackingState());
	}

	private void assertActivated(ComponentProvider bookmarks) {
		assertEquals("The active provider was not restored correctly", bookmarks,
			spyProviderActivator.lastActivated);
	}

	private void performPreviousProviderAction() {
		performAction(previousProviderAction, true);
		waitForSwing();
	}

	private void assertPreviousProviderActionEnabled() {
		assertTrue(
			"'" + ProviderNavigationPlugin.GO_TO_LAST_ACTIVE_COMPONENT_ACTION_NAME + "'" +
				" should be enabled when there is a previous provider set",
			previousProviderAction.isEnabledForContext(new ActionContext()));
	}

	private void assertPreviousProviderActionNotEnabled() {
		assertFalse(
			"'" + ProviderNavigationPlugin.GO_TO_LAST_ACTIVE_COMPONENT_ACTION_NAME + "'" +
				" should not be enabled when there is no previous provider set",
			previousProviderAction.isEnabledForContext(new ActionContext()));
	}

	private ComponentProvider activateProvider(String name) {

		waitForSwing();
		ComponentProvider provider = tool.getComponentProvider(name);
		assertNotNull(provider);

		tool.showComponentProvider(provider, true);
		runSwing(() -> forceActivate(provider));
		waitForSwing();
		return provider;
	}

	private void forceActivate(ComponentProvider provider) {
		ActionContext context = new ActionContext(provider);
		for (DockingContextListener l : testContextListeners) {
			l.contextChanged(context);
		}
	}

	private class SpyProviderActivator implements Consumer<ComponentProvider> {

		private ComponentProvider lastActivated;

		@Override
		public void accept(ComponentProvider c) {
			lastActivated = c;
			forceActivate(c);
		}
	}
}
