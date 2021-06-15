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
package docking.action;

import static org.junit.Assert.*;

import javax.swing.KeyStroke;

import org.junit.Test;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import resources.Icons;

public class ActionBuilderTest {
	private int actionCount = 0;

	@Test
	public void testDescription() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.description("foo")
				.onAction(e -> actionCount++)
				.build();
		assertEquals("foo", action.getDescription());
	}

	@Test
	public void testMenuPath() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.menuPath("foo", "bar")
				.onAction(e -> actionCount++)
				.build();

		MenuData data = action.getMenuBarData();
		assertEquals("foo->bar", data.getMenuPathAsString());
	}

	@Test
	public void testMenuGroup() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.menuPath("foo", "bar")
				.menuGroup("A", "B")
				.onAction(e -> actionCount++)
				.build();

		MenuData data = action.getMenuBarData();
		assertEquals("A", data.getMenuGroup());
		assertEquals("B", data.getMenuSubGroup());
	}

	@Test
	public void testMenuIcon() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.menuPath("foo", "bar")
				.menuIcon(Icons.ADD_ICON)
				.onAction(e -> actionCount++)
				.build();

		MenuData data = action.getMenuBarData();
		assertEquals(Icons.ADD_ICON, data.getMenuIcon());
	}

	@Test
	public void testMenuMnemonic() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.menuPath("foo", "bar")
				.menuMnemonic(5)
				.onAction(e -> actionCount++)
				.build();

		MenuData data = action.getMenuBarData();
		assertEquals(5, data.getMnemonic());
	}

	@Test
	public void testPopupPath() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.popupMenuPath("foo", "bar")
				.onAction(e -> actionCount++)
				.build();

		MenuData data = action.getPopupMenuData();
		assertEquals("foo->bar", data.getMenuPathAsString());
	}

	@Test
	public void testPopupGroup() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.popupMenuPath("foo", "bar")
				.popupMenuGroup("A", "B")
				.onAction(e -> actionCount++)
				.build();

		MenuData data = action.getPopupMenuData();
		assertEquals("A", data.getMenuGroup());
		assertEquals("B", data.getMenuSubGroup());
	}

	@Test
	public void testPopupIcon() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.popupMenuPath("foo", "bar")
				.popupMenuIcon(Icons.ADD_ICON)
				.onAction(e -> actionCount++)
				.build();

		MenuData data = action.getPopupMenuData();
		assertEquals(Icons.ADD_ICON, data.getMenuIcon());
	}

	@Test
	public void testToolbarIcon() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.toolBarIcon(Icons.ADD_ICON)
				.onAction(e -> actionCount++)
				.build();

		ToolBarData data = action.getToolBarData();
		assertEquals(Icons.ADD_ICON, data.getIcon());
	}

	@Test
	public void testToolbarGroup() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.toolBarIcon(Icons.ADD_ICON)
				.toolBarGroup("A", "B")
				.onAction(e -> actionCount++)
				.build();

		ToolBarData data = action.getToolBarData();
		assertEquals("A", data.getToolBarGroup());
		assertEquals("B", data.getToolBarSubGroup());
	}

	@Test
	public void testKeyBindingKeyStroke() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.keyBinding(KeyStroke.getKeyStroke("A"))
				.onAction(e -> actionCount++)
				.build();

		assertEquals(KeyStroke.getKeyStroke("A"), action.getKeyBinding());
	}

	@Test
	public void testKeyBindingKeyString() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.keyBinding("ALT A")
				.onAction(e -> actionCount++)
				.build();

		assertEquals(KeyStroke.getKeyStroke("alt pressed A"), action.getKeyBinding());
	}

	@Test
	public void testOnAction() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.onAction(e -> actionCount = 6)
				.build();

		assertEquals(0, actionCount);
		action.actionPerformed(new ActionContext());
		assertEquals(6, actionCount);
	}

	@Test
	public void testEnabled() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.enabled(true)
				.onAction(e -> actionCount++)
				.build();
		assertTrue(action.isEnabled());

		action = new ActionBuilder("Test", "Test")
				.enabled(false)
				.onAction(e -> actionCount++)
				.build();
		assertFalse(action.isEnabled());

	}

	@Test
	public void testEnabledWhen() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.enabledWhen(c -> c.getContextObject() == this)
				.onAction(e -> actionCount++)
				.build();

		assertTrue(action.isEnabledForContext(new ActionContext(null, this, null)));
		assertFalse(action.isEnabledForContext(new ActionContext()));
	}

	@Test
	public void testValidContextWhen() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.validContextWhen(c -> c.getContextObject() == this)
				.onAction(e -> actionCount++)
				.build();

		assertTrue(action.isValidContext(new ActionContext(null, this, null)));
		assertFalse(action.isValidContext(new ActionContext()));
	}

	@Test
	public void testPopupWhen() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.popupWhen(c -> c.getContextObject() == this)
				.onAction(e -> actionCount++)
				.build();

		assertTrue(action.isAddToPopup(new ActionContext(null, this, null)));
		assertFalse(action.isAddToPopup(new ActionContext()));
	}

	@Test
	public void testWithContext() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.withContext(FooActionContext.class)
				.enabledWhen(c -> c.foo())
				.onAction(e -> actionCount++)
				.build();

		assertFalse(action.isEnabledForContext(new ActionContext()));
		assertTrue(action.isEnabledForContext(new FooActionContext()));
	}

	@Test
	public void testManualEnablement() {
		DockingAction action = new ActionBuilder("Test", "Test")
				.onAction(e -> actionCount++)
				.enabled(false)
				.build();

		assertFalse(action.isEnabledForContext(new ActionContext()));
		action.setEnabled(true);
		assertTrue(action.isEnabledForContext(new ActionContext()));
		action.setEnabled(true);
		assertTrue(action.isEnabledForContext(new ActionContext()));
	}

	static class FooActionContext extends ActionContext {
		public boolean foo() {
			return true;
		}

	}
}
