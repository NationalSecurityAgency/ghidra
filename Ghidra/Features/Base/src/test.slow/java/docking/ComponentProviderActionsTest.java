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

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.Set;

import javax.swing.*;

import org.junit.*;

import docking.action.*;
import docking.actions.KeyEntryDialog;
import docking.actions.ToolActions;
import docking.tool.util.DockingToolConstants;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.*;
import resources.Icons;
import resources.ResourceManager;

public class ComponentProviderActionsTest extends AbstractGhidraHeadedIntegrationTest {

	// note: this has to happen after the test framework is initialized, so it cannot be static
	private final Icon ICON = ResourceManager.loadImage("images/refresh.png");
	private static final String PROVIDER_NAME = "Test Action Provider";
	private static final KeyStroke CONTROL_T =
		KeyStroke.getKeyStroke(KeyEvent.VK_T, DockingUtils.CONTROL_KEY_MODIFIER_MASK);

	private TestEnv env;
	private PluginTool tool;
	private TestActionsComponentProvider provider;
	private SpyErrorLogger spyLogger = new SpyErrorLogger();

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.showTool();

		//tool = env.launchDefaultTool();
		provider = new TestActionsComponentProvider(tool);

		Msg.setErrorLogger(spyLogger);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testIcon_WithIcon_BeforeAddedToTool() {

		setIcon(ICON);

		showProvider();

		assertWindowMenuActionHasIcon(ICON);
	}

	@Test
	public void testIcon_WithIcon_AfterAddedToTool() {

		setIcon(null);

		showProvider();
		assertWindowMenuActionHasIcon(Icons.EMPTY_ICON);

		setIcon(ICON);
		assertWindowMenuActionHasIcon(ICON);
	}

	@Test
	public void testIcon_WithoutIcon() {
		showProvider();
		assertWindowMenuActionHasIcon(Icons.EMPTY_ICON);
	}

	@Test
	public void testSetKeyBinding_DirectlyOnProvider() {
		//
		// This is how clients set key bindings on providers, as desired, when constructing them
		//

		KeyStroke defaultKs = CONTROL_T;
		setDefaultKeyBinding(defaultKs);

		showProvider();

		assertProviderKeyStroke(defaultKs);
		assertOptionsKeyStroke(defaultKs);
		assertMenuItemHasKeyStroke(defaultKs);
	}

	@Test
	public void testSetKeyBinding_DirectlyOnProvider_TransientProvider() {
		//
		// Transient providers cannot have key bindings
		//
		switchToTransientProvider();

		setErrorsExpected(true);
		setDefaultKeyBinding(CONTROL_T);
		setErrorsExpected(false);

		showProvider();

		spyLogger.assertLogMessage("Transient", "cannot", "key", "binding");
	}

	@Test
	public void testSetTransientAfterSettingKeyBinding() {

		setDefaultKeyBinding(CONTROL_T);

		setErrorsExpected(true);
		switchToTransientProvider();
		setErrorsExpected(false);

		showProvider();

		spyLogger.assertLogMessage("Transient", "not", "key", "binding");
	}

	@Test(expected = IllegalStateException.class)
	public void testSetTransientAfterAddedProviderToTheTool() {

		showProvider();
		switchToTransientProvider(); // exception
	}

	@Test
	public void testSetKeyBinding_ViaDialog_FromWindowMenu() {

		showProvider();

		KeyStroke newKs = CONTROL_T;
		setKeyBindingViaF4Dialog_FromWindowsMenu(newKs);

		assertProviderKeyStroke(newKs);
		assertOptionsKeyStroke(newKs);
		assertMenuItemHasKeyStroke(newKs);
	}

	@Test
	public void testSetKeyBinding_ViaDialog_FromWindowMenu_ThenFireKeyEventToShowProvider() {

		showProvider();

		KeyStroke newKs = CONTROL_T;
		setKeyBindingViaF4Dialog_FromWindowsMenu(newKs);

		hideProvider();
		triggerKey(tool.getToolFrame(), CONTROL_T);
		assertProviderIsActive();
	}

	@Test
	public void testSetKeyBinding_ViaDialog_FromWindowMenu_ToAlreadyBoundAction() {

		//
		// Test the conflicting key binding use case
		// 

		HasDefaultKeyBindingComponentProvider otherProvider =
			new HasDefaultKeyBindingComponentProvider(tool);
		otherProvider.setVisible(true);

		showProvider();

		KeyStroke newKs = CONTROL_T;
		applyBindingToDialog_FromWindowsMenu(newKs);

		assertCollisionsWithKeyStroke();
	}

	@Test
	public void testSetKeyBinding_ViaOptions_WithoutToolbarAction() {

		showProvider();

		KeyStroke newKs = CONTROL_T;
		setOptionsKeyStroke(newKs);

		assertProviderKeyStroke(newKs);
		assertOptionsKeyStroke(newKs);
		assertMenuItemHasKeyStroke(newKs);
		assertNoToolbarAction();
	}

	@Test
	public void testSetKeyBinding_ViaOptions_WithToolbarAction() {

		setToolbarIcon(ICON);
		showProvider();

		KeyStroke newKs = CONTROL_T;
		setOptionsKeyStroke(newKs);

		assertProviderKeyStroke(newKs);
		assertOptionsKeyStroke(newKs);
		assertMenuItemHasKeyStroke(newKs);
		assertToolbarAction();
	}

	@Test
	public void testSetKeyBinding_ViaDialog_FromToolBar() {

		setToolbarIcon(ICON);
		showProvider();

		KeyStroke newKs = CONTROL_T;
		setKeyBindingViaF4Dialog_FromToolToolbar(newKs);

		assertProviderKeyStroke(newKs);
		assertOptionsKeyStroke(newKs);
		assertMenuItemHasKeyStroke(newKs);
	}

	@Test
	public void testSetKeyBinding_TransientProvider_CannotBeSetFromWindowMenu() {

		switchToTransientProvider();
		showProvider();

		assertCannotShowKeyBindingDialog_FromWindowsMenu();
	}

	@Test
	public void testSetKeyBinding_TransientProvider_CannotBeSetFromToolbar() {

		switchToTransientProvider();

		setErrorsExpected(true);
		setToolbarIcon(ICON);
		setErrorsExpected(false);

		spyLogger.assertLogMessage("Transient", "not", "toolbar");
	}

	@Test
	public void testDefaultKeyBindingAppearsInWindowMenu() {

		setDefaultKeyBinding(CONTROL_T);
		showProvider();
		assertWindowMenuActionHasKeyBinding(CONTROL_T);
	}

	@Test
	public void testAddToToolbar_WithoutIcon() {

		runSwing(() -> provider.addToToolbar());

		try {
			setErrorsExpected(true);
			runSwingWithException(this::showProvider);
			setErrorsExpected(false);
			fail();
		}
		catch (Throwable t) {
			// good
		}
	}

	@Test
	public void testSetIcon_NullIconWithToolbarAction() {

		setIcon(ICON);
		runSwing(() -> provider.addToToolbar());
		showProvider();

		try {
			setErrorsExpected(true);
			runSwingWithException(() -> provider.setIcon(null));
			setErrorsExpected(false);
			fail("Expected an exception passing a null icon when specifying a toolbar action");
		}
		catch (Throwable t) {
			// expected
		}
	}

	@Test
	public void testSetIcon_WithToolbarAction() {
		setToolbarIcon(ICON);
		showProvider();

		assertWindowMenuActionHasIcon(ICON);
		assertToolbarActionHasIcon(ICON);
	}

	@Test
	public void testSetIcon_WithToolbarAction_AfterActionHasBeenAddedToToolbar() {

		//
		// We currently do not prevent providers from changing their icons.  Make sure we respond
		// to changes correctly.
		//

		setToolbarIcon(ICON);
		showProvider();

		Icon newIcon = Icons.COLLAPSE_ALL_ICON;
		setIcon(newIcon);

		assertWindowMenuActionHasIcon(newIcon);
		assertToolbarActionHasIcon(newIcon);
	}

	@Test
	public void testSetCloseButtonKeyBinding() {

		showProvider();

		KeyStroke controlEsc =
			KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, DockingUtils.CONTROL_KEY_MODIFIER_MASK);
		setKeyBindingViaF4Dialog_FromCloseButton(controlEsc);

		// Note: there may be a test focus issue here.  If this test fails sporadically due to 
		// how the action context is generated (it depends on focus).  It is only useful to fail
		// here in development mode.
		triggerKey(provider.getComponent(), controlEsc);
		assertProviderIsHidden_InNonBatchMode();
	}

	@Test
	public void testEveryCloseButtonsActionContext() {

		// grab the tool that has all the provider's loaded
		env.closeTool(tool);
		tool = env.launchDefaultTool();

		DockingWindowManager dwm = tool.getWindowManager();
		PlaceholderManager pm = dwm.getPlaceholderManager();
		Set<ComponentProvider> allProviders = pm.getActiveProviders();
		for (ComponentProvider cp : allProviders) {
			ActionContext context = cp.getActionContext(null);
			if (context == null) {
				continue; // a null context is allowed
			}

			// this is a rule we need for context to work as intended for some actions (like the
			// close button)
			assertSame("Component provider did not make itself the context's provider",
				context.getComponentProvider(), cp);
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void switchToTransientProvider() {
		provider.setTransient();
	}

	private void showProvider() {
		provider.addToTool();
		tool.showComponentProvider(provider, true);
		waitForSwing();
		waitForCondition(() -> provider.isVisible());
	}

	private void hideProvider() {
		tool.showComponentProvider(provider, false);
		waitForSwing();
	}

	private void setDefaultKeyBinding(KeyStroke defaultKs) {
		runSwing(() -> provider.setKeyBinding(new KeyBindingData(defaultKs)));
	}

	private void setIcon(Icon icon) {
		runSwing(() -> provider.setIcon(icon));
	}

	private void setToolbarIcon(Icon icon) {
		runSwing(() -> {
			provider.setIcon(icon);
			provider.addToToolbar();
		});
	}

	private DockingActionIf getShowProviderAction() {

		DockingActionIf showProviderAction =
			getAction(tool, provider.getOwner(), provider.getName());
		assertNotNull("Could not find action to show ", showProviderAction);
		return showProviderAction;
	}

	private DockingActionIf getWindowMenuShowProviderAction() {
		waitForSwing();
		DockingActionIf action = waitFor(() -> {
			Set<DockingActionIf> actions = getActionsByName(tool, PROVIDER_NAME);

			//@formatter:off
			return actions
				.stream()
				.filter(a -> a.getOwner().equals(DockingWindowManager.DOCKING_WINDOWS_OWNER))
				.findFirst()
				.orElseGet(() -> null)
				;
			//@formatter:on
		});

		assertNotNull("Window menu action not installed for provider", action);
		assertTrue(action.getClass().getSimpleName().contains("ShowComponentAction"));
		return action;
	}

	private DockingActionIf getToolbarShowProviderAction() {

		DockingWindowManager dwm = tool.getWindowManager();
		ActionToGuiMapper guiActions =
			(ActionToGuiMapper) getInstanceField("actionToGuiMapper", dwm);
		GlobalMenuAndToolBarManager toolbarManager =
			(GlobalMenuAndToolBarManager) getInstanceField("menuAndToolBarManager", guiActions);
		DockingActionIf action = provider.getShowProviderAction();
		DockingActionIf toolbarAction = toolbarManager.getToolbarAction(action.getName());
		return toolbarAction;
	}

	private void setOptionsKeyStroke(KeyStroke newKs) {
		ToolOptions keyOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);

		// shared option name/format: "Provider Name (Shared)" - the shared action's owner is the Tool
		runSwing(() -> keyOptions.setKeyStroke(provider.getName() + " (Shared)", newKs));
		waitForSwing();
	}

	private void assertProviderIsActive() {

		assertTrue("Component provider is not showing", runSwing(() -> tool.isVisible(provider)));

		// note: we can't call 'isActive()' due to focus issues in parallel testing
		//assertTrue("The test provider is not showing and focused",
		//	runSwing(() -> tool.isActive(provider)));
	}

	private void assertProviderIsHidden_InNonBatchMode() {

		boolean isVisible = runSwing(() -> tool.isVisible(provider));
		if (!SystemUtilities.isInTestingBatchMode()) {
			assertFalse("The test provider is showing, but should be hidden", isVisible);
			return;
		}

		if (isVisible) {
			Msg.error(this,
				"Provider should not be visible after pressing the 'close provider' key bindings");
		}
	}

	private void assertNoToolbarAction() {
		assertNull("No toolbar action found for provider", getToolbarShowProviderAction());
	}

	private void assertToolbarAction() {
		assertNotNull("No toolbar action found for provider", getToolbarShowProviderAction());
	}

	private void assertProviderKeyStroke(KeyStroke expectedKs) {

		DockingActionIf action = getShowProviderAction();
		KeyStroke actionKs = action.getKeyBinding();
		assertEquals(expectedKs, actionKs);
	}

	private void assertOptionsKeyStroke(KeyStroke expectedKs) {

		ToolOptions options = getKeyBindingOptions();

		// Option name: the action name with the 'Shared' owner
		String fullName = provider.getName() + " (Shared)";
		KeyStroke optionsKs = runSwing(() -> options.getKeyStroke(fullName, null));
		assertEquals("Key stroke in options does not match expected key stroke", expectedKs,
			optionsKs);
	}

	private void assertWindowMenuActionHasIcon(Icon expected) {
		DockingActionIf action = getWindowMenuShowProviderAction();
		assertEquals("Windows menu icons for provider does not match the value set on the provider",
			expected, action.getMenuBarData().getMenuIcon());
	}

	private void assertToolbarActionHasIcon(Icon expected) {
		DockingActionIf action = getToolbarShowProviderAction();
		assertNotNull("No toolbar action found; it should be there", action);
		ToolBarData tbData = action.getToolBarData();
		assertEquals(expected, tbData.getIcon());
	}

	private void assertWindowMenuActionHasKeyBinding(KeyStroke ks) {
		DockingActionIf action = getWindowMenuShowProviderAction();
		assertEquals(
			"Windows menu key bindings for provider does not match the value set on the provider",
			ks, action.getKeyBinding());
	}

	private void assertCannotShowKeyBindingDialog_FromWindowsMenu() {
		// simulate the user mousing over the 'Window' menu's action
		DockingActionIf windowMenuAction = getWindowMenuShowProviderAction();
		DockingWindowManager.setMouseOverAction(windowMenuAction);

		performLaunchKeyStrokeDialogAction();
		DialogComponentProvider warningDialog = waitForDialogComponent("Unable to Set Keybinding");
		close(warningDialog);
	}

	private void setKeyBindingViaF4Dialog_FromWindowsMenu(KeyStroke ks) {

		// simulate the user mousing over the 'Window' menu's action
		DockingActionIf windowMenuAction = getWindowMenuShowProviderAction();
		DockingWindowManager.setMouseOverAction(windowMenuAction);

		performLaunchKeyStrokeDialogAction();
		KeyEntryDialog dialog = waitForDialogComponent(KeyEntryDialog.class);

		runSwing(() -> dialog.setKeyStroke(ks));

		pressButtonByText(dialog, "OK");

		assertFalse("Invalid key stroke: " + ks, runSwing(() -> dialog.isVisible()));
	}

	private void setKeyBindingViaF4Dialog_FromCloseButton(KeyStroke ks) {

		// simulate the user mousing over the toolbar button		
		DockingActionIf closeAction = getAction(tool, provider.getOwner(), "Close Window");
		assertNotNull("Provider action not installed in toolbar", closeAction);

		DockingWindowManager.setMouseOverAction(closeAction);

		performLaunchKeyStrokeDialogAction();
		KeyEntryDialog dialog = waitForDialogComponent(KeyEntryDialog.class);

		runSwing(() -> dialog.setKeyStroke(ks));

		pressButtonByText(dialog, "OK");
		waitForSwing();

		assertFalse("Invalid key stroke: " + ks, runSwing(() -> dialog.isVisible()));
	}

	private void applyBindingToDialog_FromWindowsMenu(KeyStroke ks) {
		DockingActionIf windowMenuAction = getWindowMenuShowProviderAction();
		DockingWindowManager.setMouseOverAction(windowMenuAction);

		performLaunchKeyStrokeDialogAction();
		KeyEntryDialog dialog = waitForDialogComponent(KeyEntryDialog.class);

		runSwing(() -> dialog.setKeyStroke(ks));
	}

	private void assertCollisionsWithKeyStroke() {
		KeyEntryDialog dialog = waitForDialogComponent(KeyEntryDialog.class);

		JTextPane collisionPane = (JTextPane) getInstanceField("collisionPane", dialog);
		String collisionText = runSwing(() -> collisionPane.getText());
		assertTrue(collisionText.contains("Actions mapped to"));
	}

	private void assertMenuItemHasKeyStroke(KeyStroke expected) {

		DockingActionIf action = getWindowMenuShowProviderAction();
		assertEquals(
			"Windows menu key binding for provider does not match the value of the provider",
			expected, action.getKeyBinding());
	}

	private void setKeyBindingViaF4Dialog_FromToolToolbar(KeyStroke ks) {

		// simulate the user mousing over the toolbar button		
		DockingActionIf toolbarAction = getToolbarShowProviderAction();
		assertNotNull("Provider action not installed in toolbar", toolbarAction);
		DockingWindowManager.setMouseOverAction(toolbarAction);

		performLaunchKeyStrokeDialogAction();
		KeyEntryDialog dialog = waitForDialogComponent(KeyEntryDialog.class);

		runSwing(() -> dialog.setKeyStroke(ks));

		pressButtonByText(dialog, "OK");

		assertFalse("Invalid key stroke: " + ks, runSwing(() -> dialog.isVisible()));
	}

	private void performLaunchKeyStrokeDialogAction() {
		ToolActions toolActions = (ToolActions) ((AbstractDockingTool) tool).getToolActions();
		Action action = toolActions.getAction(KeyStroke.getKeyStroke("F4"));
		assertNotNull(action);
		runSwing(() -> action.actionPerformed(new ActionEvent(this, 0, "")), false);
	}

	private ToolOptions getKeyBindingOptions() {
		return tool.getOptions(DockingToolConstants.KEY_BINDINGS);
	}

	private class TestActionsComponentProvider extends ComponentProvider {

		private JComponent component = new JTextField("Hey!");

		TestActionsComponentProvider(Tool tool) {
			super(tool, PROVIDER_NAME, "Fooberry Plugin");
		}

		@Override
		public JComponent getComponent() {
			return component;
		}
	}

	private class HasDefaultKeyBindingComponentProvider extends ComponentProvider {
		private JComponent component = new JTextField("Hey!");

		HasDefaultKeyBindingComponentProvider(Tool tool) {
			super(tool, HasDefaultKeyBindingComponentProvider.class.getSimpleName(),
				"Fooberry Plugin");

			setKeyBinding(new KeyBindingData(CONTROL_T));
		}

		@Override
		public JComponent getComponent() {
			return component;
		}
	}
}
