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
package docking.actions;

import static org.junit.Assert.*;

import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Set;

import javax.swing.JComponent;
import javax.swing.KeyStroke;

import org.apache.commons.collections4.IterableUtils;
import org.junit.Before;
import org.junit.Test;

import docking.*;
import docking.action.*;
import docking.test.AbstractDockingTest;
import docking.tool.util.DockingToolConstants;
import ghidra.framework.options.ToolOptions;
import ghidra.util.Msg;
import ghidra.util.SpyErrorLogger;
import ghidra.util.exception.AssertException;

public class SharedKeyBindingDockingActionTest extends AbstractDockingTest {

	private static final String NON_SHARED_NAME = "Non-Shared Action Name";
	private static final String SHARED_NAME = "Shared Action Name";
	private static final String SHARED_OWNER = SharedStubKeyBindingAction.SHARED_OWNER;

	// format:  getName() + " (" + getOwner() + ")";
	private static final String SHARED_FULL_NAME = SHARED_NAME + " (" + SHARED_OWNER + ")";

	private static final KeyStroke DEFAULT_KS_1 = KeyStroke.getKeyStroke(KeyEvent.VK_A, 0);
	private static final KeyStroke DEFAULT_KS_DIFFERENT_THAN_1 =
		KeyStroke.getKeyStroke(KeyEvent.VK_B, 0);
	private static final String OWNER_1 = "Owner1";
	private static final String OWNER_2 = "Owner2";

	private SpyErrorLogger spyLogger = new SpyErrorLogger();

	private Tool tool;

	@Before
	public void setUp() {
		tool = new FakeDockingTool();

		Msg.setErrorLogger(spyLogger);
	}

	@Test
	public void testSharedKeyBinding_SameDefaultKeyBindings() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action2);

		assertNoLoggedMessages();
		assertKeyBinding(action1, DEFAULT_KS_1);
		assertKeyBinding(action2, DEFAULT_KS_1);
		assertSharedStubInTool();
	}

	@Test
	public void testSharedKeyBinding_OptionsChange() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action2);

		KeyStroke newKs = KeyStroke.getKeyStroke(KeyEvent.VK_Z, 0);
		setSharedKeyBinding(newKs);

		assertNoLoggedMessages();
		assertKeyBinding(action1, newKs);
		assertKeyBinding(action2, newKs);
		assertSharedStubInTool();
	}

	@Test
	public void testSharedKeyBinding_DifferentDefaultKeyBindings() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_DIFFERENT_THAN_1);

		tool.addAction(action1);
		tool.addAction(action2);

		// both bindings should keep the first one that was set when they are different
		assertImproperDefaultBindingMessage();
		assertKeyBinding(action1, DEFAULT_KS_1);
		assertKeyBinding(action2, DEFAULT_KS_1);
		assertSharedStubInTool();
	}

	@Test
	public void testSharedKeyBinding_NoDefaultKeyBindings() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, null);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, null);

		tool.addAction(action1);
		tool.addAction(action2);

		// both bindings are null; this is allowed
		assertNoLoggedMessages();
		assertKeyBinding(action1, null);
		assertKeyBinding(action2, null);
		assertSharedStubInTool();
	}

	@Test
	public void testSharedKeyBinding_OneDefaultOneUndefinedDefaultKeyBinding() {
		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, null);

		tool.addAction(action1);
		tool.addAction(action2);

		// both bindings should keep the first one that was set when they are different
		assertImproperDefaultBindingMessage();
		assertKeyBinding(action1, DEFAULT_KS_1);
		assertKeyBinding(action2, DEFAULT_KS_1);
		assertSharedStubInTool();
	}

	@Test
	public void testSharedKeyBinding_RemoveAction() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action2);

		tool.removeAction(action1);

		assertActionNotInTool(action1);
		assertActionInTool(action2);

		tool.removeAction(action2);
		assertActionNotInTool(action2);

		assertNoSharedKeyBindingStubInstalled(action1);
	}

	@Test
	public void testSharedKeyBinding_AddSameActionTwice() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);

		tool.addAction(action1);

		try {
			tool.addAction(action1);
			fail("Did not get expected exception");
		}
		catch (AssertException e) {
			// expected
		}

		assertOnlyOneVersionOfActionInTool(action1);

		assertNoLoggedMessages();
		assertKeyBinding(action1, DEFAULT_KS_1);
		assertSharedStubInTool();
	}

	@Test
	public void testSharedKeyBinding_OnlyOneEntryInOptions() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action2);

		// verify that the actions are not in the options, but that the shared action is
		ToolOptions keyOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);
		List<String> names = keyOptions.getOptionNames();
		assertTrue(names.contains(SHARED_FULL_NAME));
		assertFalse(names.contains(action1.getFullName()));
		assertFalse(names.contains(action2.getFullName()));
	}

	@Test
	public void testSharedKeyBinding_AddActionAfterOptionHasChanged() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		KeyStroke newKs = KeyStroke.getKeyStroke(KeyEvent.VK_Z, 0);
		setSharedKeyBinding(newKs);

		assertKeyBinding(action1, newKs);

		// verify the newly added keybinding gets the newly changed option
		tool.addAction(action2);
		assertKeyBinding(action2, newKs);
		assertNoLoggedMessages();
	}

	@Test
	public void testSharedKeyBinding_AddActionAfterOptionHasChanged_RepeatAddRemove() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_1);

		tool.addAction(action1);
		KeyStroke newKs = KeyStroke.getKeyStroke(KeyEvent.VK_Z, 0);
		setSharedKeyBinding(newKs);

		assertKeyBinding(action1, newKs);

		// verify the newly added keybinding gets the newly changed option
		tool.addAction(action2);
		assertKeyBinding(action2, newKs);
		assertNoLoggedMessages();

		tool.removeAction(action2);
		assertActionNotInTool(action2);

		tool.addAction(action2);
		assertKeyBinding(action2, newKs);
		assertNoLoggedMessages();
	}

	@Test
	public void testSharedKeyBinding_SameDefaultKeyBindings_LocalAction() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_1);

		DummyComponentProvider provider = new DummyComponentProvider();
		tool.addLocalAction(provider, action1);
		tool.addLocalAction(provider, action2);

		assertNoLoggedMessages();
		assertKeyBinding(action1, DEFAULT_KS_1);
		assertKeyBinding(action2, DEFAULT_KS_1);
		assertSharedStubInTool();
	}

	@Test
	public void testSharedKeyBinding_RemoveAction_LocalAction() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_1);

		DummyComponentProvider provider = new DummyComponentProvider();
		tool.addLocalAction(provider, action1);
		tool.addLocalAction(provider, action2);

		tool.removeLocalAction(provider, action1);

		assertActionNotInTool(action1);
		assertActionInTool(action2);

		tool.removeLocalAction(provider, action2);
		assertActionNotInTool(action2);

		assertNoSharedKeyBindingStubInstalled(action1);
	}

	@Test
	public void testSharedKeyBinding_RemoveComonentActions() {

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action2 = new SharedNameAction(OWNER_2, DEFAULT_KS_1);

		DummyComponentProvider provider = new DummyComponentProvider();
		tool.addLocalAction(provider, action1);
		tool.addLocalAction(provider, action2);
		assertActionInTool(action1);
		assertActionInTool(action2);

		tool.removeComponentProvider(provider);

		assertActionNotInTool(action1);
		assertActionNotInTool(action2);

		assertNoSharedKeyBindingStubInstalled(action1);
	}

	@Test
	public void testSharedKeyBinding_SameActionAddedTwice() {
		//
		// We support adding the same action twice.  (This can happen when a transient component
		// provider is repeatedly shown, such as a search results provider.)   Make sure we get
		// a warning if the same action is added twice, but with different key bindings.
		//
		// Note: in this context, two actions are considered to be the same if they share the 
		//       same name and owner.
		//

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action1Copy = new SharedNameAction(OWNER_1, DEFAULT_KS_1);

		tool.addAction(action1);
		tool.addAction(action1Copy);
		assertActionInTool(action1);
		assertActionInTool(action1Copy);

		assertNoLoggedMessages();

		tool.removeAction(action1);
		assertActionNotInTool(action1);
		assertActionInTool(action1Copy);

		tool.removeAction(action1Copy);
		assertActionNotInTool(action1Copy);
	}

	@Test
	public void testSharedKeyBinding_DifferentActionsWithSameFullName() {
		//
		// We support adding the same action twice.  (This can happen when a transient component
		// provider is repeatedly shown, such as a search results provider.)   Make sure we get
		// a warning if the same action is added twice, but with different key bindings.
		//
		// Note: in this context, two actions are considered to be the same if they share the 
		//       same name and owner.
		//

		SharedNameAction action1 = new SharedNameAction(OWNER_1, DEFAULT_KS_1);
		SharedNameAction action1Copy = new SharedNameAction(OWNER_1, DEFAULT_KS_DIFFERENT_THAN_1);

		tool.addAction(action1);
		tool.addAction(action1Copy);
		assertActionInTool(action1);
		assertActionInTool(action1Copy);

		assertImproperDefaultBindingMessage();

		tool.removeAction(action1);
		assertActionNotInTool(action1);
		assertActionInTool(action1Copy);

		tool.removeAction(action1Copy);
		assertActionNotInTool(action1Copy);
	}

	@Test
	public void testNonSharedKeyBinding_DifferentActionsWithSameFullName() {
		//
		// We support adding the same action twice.  (This can happen when a transient component
		// provider is repeatedly shown, such as a search results provider.)   Make sure we get
		// a warning if the same action is added twice, but with different key bindings.
		//
		// Note: in this context, two actions are considered to be the same if they share the 
		//       same name and owner.
		//

		TestNonSharedAction action1 = new TestNonSharedAction(OWNER_1, DEFAULT_KS_1);
		TestNonSharedAction action1Copy =
			new TestNonSharedAction(OWNER_1, DEFAULT_KS_DIFFERENT_THAN_1);

		tool.addAction(action1);
		tool.addAction(action1Copy);
		assertActionInTool(action1);
		assertActionInTool(action1Copy);

		assertImproperDefaultBindingMessage();

		tool.removeAction(action1);
		assertActionNotInTool(action1);
		assertActionInTool(action1Copy);

		tool.removeAction(action1Copy);
		assertActionNotInTool(action1Copy);
	}

	@Test
	public void testNonKeyBindingAction_CannotSetKeyBinding() {

		DockingAction action = new DockingAction("Test Action", "Test Action Owner", false) {
			@Override
			public void actionPerformed(ActionContext context) {
				// stub
			}
		};

		action.setKeyBindingData(new KeyBindingData(DEFAULT_KS_1));
		assertNull(action.getKeyBindingData());
		spyLogger.assertLogMessage("does", "not", "support", "bindings");
	}

	@Test
	public void testNonKeyBindingAction_CannotSetKeyBinding_NullBinding() {

		DockingAction action = new DockingAction("Test Action", "Test Action Owner", false) {
			@Override
			public void actionPerformed(ActionContext context) {
				// stub
			}
		};

		action.setKeyBindingData(null);
		assertNull(action.getKeyBindingData());
		spyLogger.assertLogMessage("does", "not", "support", "bindings");
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertSharedStubInTool() {
		ToolActions actionManager = (ToolActions) getInstanceField("toolActions", tool);
		DockingActionIf action = actionManager.getSharedStubKeyBindingAction(SHARED_NAME);
		assertNotNull("Shared action stub is not in the tool", action);
	}

	private void assertOnlyOneVersionOfActionInTool(DockingActionIf action) {

		// this  method will fail if more than one action is registered
		DockingActionIf registeredAction = getAction(tool, action.getOwner(), action.getName());
		assertNotNull("There should be only one instance of this action in the tool: " + action,
			registeredAction);
	}

	private void assertActionInTool(DockingActionIf action) {

		Set<DockingActionIf> actions = getActionsByName(tool, action.getName());
		for (DockingActionIf toolAction : actions) {
			if (toolAction == action) {
				return;
			}
		}

		fail("Action is not in the tool: " + action);
	}

	private void assertActionNotInTool(DockingActionIf action) {
		Set<DockingActionIf> actions = getActionsByName(tool, action.getName());
		for (DockingActionIf toolAction : actions) {
			assertNotSame(toolAction, action);
		}
	}

	private void assertNoSharedKeyBindingStubInstalled(DockingActionIf action) {

		String name = action.getName();
		String owner = action.getOwner();
		DockingActionIf sharedAction = getAction(tool, owner, name);
		assertNull("There should be no actions registered for '" + name + " (" + owner + ")'",
			sharedAction);
	}

	private void setSharedKeyBinding(KeyStroke newKs) {
		ToolOptions options = getKeyBindingOptions();
		runSwing(() -> options.setKeyStroke(SHARED_FULL_NAME, newKs));
		waitForSwing();
	}

	private ToolOptions getKeyBindingOptions() {
		return tool.getOptions(DockingToolConstants.KEY_BINDINGS);
	}

	private void assertNoLoggedMessages() {
		assertTrue("Spy logger not empty: " + spyLogger, IterableUtils.isEmpty(spyLogger));
	}

	private void assertImproperDefaultBindingMessage() {
		spyLogger.assertLogMessage("shared", "key", "binding", "actions", "different", "default");
	}

	private void assertKeyBinding(SharedNameAction action, KeyStroke expectedKs) {
		assertEquals(expectedKs, action.getKeyBinding());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class SharedNameAction extends DockingAction {

		public SharedNameAction(String owner, KeyStroke ks) {
			super(SHARED_NAME, owner, KeyBindingType.SHARED);
			setKeyBindingData(new KeyBindingData(ks));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			fail("Action performed should not have been called");
		}
	}

	private class TestNonSharedAction extends DockingAction {

		public TestNonSharedAction(String owner, KeyStroke ks) {
			super(NON_SHARED_NAME, owner, KeyBindingType.INDIVIDUAL);
			setKeyBindingData(new KeyBindingData(ks));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			fail("Action performed should not have been called");
		}
	}

	private class DummyComponentProvider extends ComponentProvider {
		public DummyComponentProvider() {
			super(tool, "Dummy", "Dummy Owner");
			addToTool();
		}

		@Override
		public JComponent getComponent() {
			return null;
		}
	}
}
