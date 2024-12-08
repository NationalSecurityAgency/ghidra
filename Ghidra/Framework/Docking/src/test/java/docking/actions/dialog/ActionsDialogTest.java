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
package docking.actions.dialog;

import static org.junit.Assert.*;

import java.util.*;
import java.util.stream.Collectors;

import org.junit.Test;

import docking.ActionContext;
import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.action.builder.ActionBuilder;
import docking.test.AbstractDockingTest;
import docking.widgets.searchlist.SearchListEntry;
import resources.Icons;

public class ActionsDialogTest extends AbstractDockingTest {
	private static final boolean ENABLED = true;
	private static final boolean ADD_TO_POPUP = true;

	private List<String> triggeredActions = new ArrayList<>();
	private Set<DockingActionIf> localActions = new HashSet<>();
	private Set<DockingActionIf> globalActions = new HashSet<>();
	private TestContextA contextA = new TestContextA();
	private TestContextB contextB = new TestContextB();

	@Test
	public void testToolBarActionsForEachDisplayLevel() {
		addLocal(toolbar("A", ENABLED, contextA));
		addLocal(toolbar("B", !ENABLED, contextA));
		addLocal(toolbar("C", ENABLED, contextB));
		addLocal(toolbar("D", !ENABLED, contextB));
		addGlobal(toolbar("W", ENABLED, contextA));
		addGlobal(toolbar("X", !ENABLED, contextA));
		addGlobal(toolbar("Y", ENABLED, contextB));
		addGlobal(toolbar("Z", !ENABLED, contextB));

		// level 1 includes all local toolbar actions with a valid context
		ActionsModel model = buildModel(contextA, ActionDisplayLevel.LOCAL);
		assertEquals(2, model.getSize());
		assertModelContains(model, "A", "B");

		// level 2 includes all local and global toolbar actions with a valid context
		model.setDisplayLevel(ActionDisplayLevel.GLOBAL);
		assertEquals(4, model.getSize());
		assertModelContains(model, "A", "B", "W", "X");

		// level 3 includes all local and global toolbar actions, regardless of context
		model.setDisplayLevel(ActionDisplayLevel.ALL);
		assertEquals(8, model.getSize());
		assertModelContains(model, "A", "B", "C", "D", "W", "X", "Y", "Z");

	}

	@Test
	public void testMenuActionsForEachDisplayLevel() {
		addLocal(menuItem("A", ENABLED, contextA));
		addLocal(menuItem("B", !ENABLED, contextA));
		addLocal(menuItem("C", ENABLED, contextB));
		addLocal(menuItem("D", !ENABLED, contextB));
		addGlobal(menuItem("W", ENABLED, contextA));
		addGlobal(menuItem("X", !ENABLED, contextA));
		addGlobal(menuItem("Y", ENABLED, contextB));
		addGlobal(menuItem("Z", !ENABLED, contextB));

		// level 1 includes all local menu actions with a valid context
		ActionsModel model = buildModel(contextA, ActionDisplayLevel.LOCAL);
		assertEquals(2, model.getSize());
		assertModelContains(model, "A", "B");

		// level 2 includes all local and global menu actions with a valid context
		model.setDisplayLevel(ActionDisplayLevel.GLOBAL);
		assertEquals(4, model.getSize());
		assertModelContains(model, "A", "B", "W", "X");

		// level 3 includes all local and global menu actions
		model.setDisplayLevel(ActionDisplayLevel.ALL);
		assertEquals(8, model.getSize());
		assertModelContains(model, "A", "B", "C", "D", "W", "X", "Y", "Z");

	}

	@Test
	public void testKeyActionsForAllDisplayLevels() {
		addLocal(keyAction("A", ENABLED, contextA));
		addLocal(keyAction("B", !ENABLED, contextA));
		addLocal(keyAction("C", ENABLED, contextB));
		addLocal(keyAction("D", !ENABLED, contextB));
		addGlobal(keyAction("W", ENABLED, contextA));
		addGlobal(keyAction("X", !ENABLED, contextA));
		addGlobal(keyAction("Y", ENABLED, contextB));
		addGlobal(keyAction("Z", !ENABLED, contextB));

		// level 1 includes all local and global keybinding actions that are valid and enabled
		ActionsModel model = buildModel(contextA, ActionDisplayLevel.LOCAL);
		assertEquals(2, model.getSize());
		assertModelContains(model, "A", "W");

		// level 2 includes all local and global keybinding actions that are valid and enabled
		model.setDisplayLevel(ActionDisplayLevel.GLOBAL);
		assertEquals(2, model.getSize());
		assertModelContains(model, "A", "W");

		// level 3 includes all local and global keybinding
		model.setDisplayLevel(ActionDisplayLevel.ALL);
		assertEquals(8, model.getSize());
		assertModelContains(model, "A", "W");
		assertModelContains(model, "A", "B", "C", "D", "W", "X", "Y", "Z");

	}

	@Test
	public void testPopupActionsDisplayLOCAL() {
		addLocal(popup("A", ENABLED, ADD_TO_POPUP, contextA));
		addLocal(popup("B", ENABLED, !ADD_TO_POPUP, contextA));
		addLocal(popup("C", !ENABLED, ADD_TO_POPUP, contextA));
		addLocal(popup("D", !ENABLED, !ADD_TO_POPUP, contextA));
		addLocal(popup("E", ENABLED, ADD_TO_POPUP, contextB));
		addLocal(popup("F", ENABLED, !ADD_TO_POPUP, contextB));
		addLocal(popup("G", !ENABLED, ADD_TO_POPUP, contextB));
		addLocal(popup("H", !ENABLED, !ADD_TO_POPUP, contextB));

		addGlobal(popup("S", ENABLED, ADD_TO_POPUP, contextA));
		addGlobal(popup("T", ENABLED, !ADD_TO_POPUP, contextA));
		addGlobal(popup("U", !ENABLED, ADD_TO_POPUP, contextA));
		addGlobal(popup("V", !ENABLED, !ADD_TO_POPUP, contextA));
		addGlobal(popup("W", ENABLED, ADD_TO_POPUP, contextB));
		addGlobal(popup("X", ENABLED, !ADD_TO_POPUP, contextB));
		addGlobal(popup("Y", !ENABLED, ADD_TO_POPUP, contextB));
		addGlobal(popup("Z", !ENABLED, !ADD_TO_POPUP, contextB));

		// display level 1 includes all local and global popup actions that are valid and addToPopup
		ActionsModel model = buildModel(contextA, ActionDisplayLevel.LOCAL);
		assertEquals(4, model.getSize());
		assertModelContains(model, "A", "C", "S", "U");

		// display level 2 includes all local and global popup actions that are valid and addToPopup
		model.setDisplayLevel(ActionDisplayLevel.GLOBAL);
		assertEquals(4, model.getSize());
		assertModelContains(model, "A", "C", "S", "U");

		// display level 3 includes all local and global popup actions
		model.setDisplayLevel(ActionDisplayLevel.ALL);
		assertEquals(16, model.getSize());
		assertModelContains(model, "A", "B", "C", "D", "E", "F", "G", "H", "S", "T", "U", "V", "W",
			"X", "Y", "Z");
	}

	@Test
	public void testActionsOrganization() {
		addLocal(toolbar("A", ENABLED, contextA));
		addLocal(menuItem("B", ENABLED, contextA));
		addLocal(popup("C", ENABLED, ADD_TO_POPUP, contextA));
		addLocal(keyAction("D", ENABLED, contextA));

		addGlobal(toolbar("W", ENABLED, contextA));
		addGlobal(menuItem("X", ENABLED, contextA));
		addGlobal(popup("Y", ENABLED, ADD_TO_POPUP, contextA));
		addGlobal(keyAction("Z", ENABLED, contextA));

		ActionsModel model = buildModel(contextA, ActionDisplayLevel.ALL);
		List<String> categories = model.getCategories();
		assertEquals(6, categories.size());

		assertEquals(Arrays.asList("A"), getActionsForCategory(model, ActionGroup.LOCAL_TOOLBAR));
		assertEquals(Arrays.asList("B"), getActionsForCategory(model, ActionGroup.LOCAL_MENU));
		assertEquals(Arrays.asList("W"), getActionsForCategory(model, ActionGroup.GLOBAL_TOOLBAR));
		assertEquals(Arrays.asList("X"), getActionsForCategory(model, ActionGroup.GLOBAL_MENU));
		assertEquals(Arrays.asList("C", "Y"), getActionsForCategory(model, ActionGroup.POPUP));
		assertEquals(Arrays.asList("D", "Z"),
			getActionsForCategory(model, ActionGroup.KEYBINDING_ONLY));

	}

	@Test
	public void testFiltering() {
		addLocal(toolbar("Apple", ENABLED, contextA));
		addLocal(menuItem("Banana", ENABLED, contextA));
		addLocal(popup("Pear", ENABLED, ADD_TO_POPUP, contextA));
		addLocal(keyAction("Kiwi", ENABLED, contextA));

		ActionsModel model = buildModel(contextA, ActionDisplayLevel.ALL);
		ActionChooserDialog dialog = getSwing(() -> new ActionChooserDialog(model));

		assertEquals(4, model.getSize());

		setFilterText(dialog, "pp");

		assertEquals(1, model.getSize());
		assertEquals(Arrays.asList("Apple"), getDisplayedActionNames(model));

		setFilterText(dialog, "");
		assertEquals(4, model.getSize());

		setFilterText(dialog, "a");
		assertEquals(3, model.getSize());
		assertEquals(Arrays.asList("Apple", "Banana", "Pear"), getDisplayedActionNames(model));
	}

	@Test
	public void testApplyFilterChangeDisplayLevel() {
		addLocal(popup("APPLE ENABLED", ENABLED, ADD_TO_POPUP, contextA));
		addLocal(popup("BANANA ENABLED", ENABLED, ADD_TO_POPUP, contextA));
		addLocal(popup("APPLE DISABLED", !ENABLED, !ADD_TO_POPUP, contextA));
		addLocal(popup("BANANA DISABLED", !ENABLED, !ADD_TO_POPUP, contextA));

		ActionsModel model = buildModel(contextA, ActionDisplayLevel.LOCAL);
		ActionChooserDialog dialog = getSwing(() -> new ActionChooserDialog(model));

		assertEquals(2, model.getSize());

		setFilterText(dialog, "APPLE");

		assertEquals(1, model.getSize());
		assertEquals(Arrays.asList("APPLE ENABLED"), getDisplayedActionNames(model));

		model.setDisplayLevel(ActionDisplayLevel.ALL);

		assertEquals(2, model.getSize());
		assertEquals(Arrays.asList("APPLE DISABLED", "APPLE ENABLED"),
			getDisplayedActionNames(model));

		model.setDisplayLevel(ActionDisplayLevel.LOCAL);
		assertEquals(1, model.getSize());
		assertEquals(Arrays.asList("APPLE ENABLED"), getDisplayedActionNames(model));

		setFilterText(dialog, "");
		assertEquals(2, model.getSize());
		assertEquals(Arrays.asList("APPLE ENABLED", "BANANA ENABLED"),
			getDisplayedActionNames(model));

	}

	@Test
	public void testFilteringOnKeybinding() {
		addLocal(toolbar("Apple", ENABLED, contextA));
		addLocal(menuItem("Banana", ENABLED, contextA));
		addLocal(popup("Pear", ENABLED, ADD_TO_POPUP, contextA));
		addLocal(keyAction("Kiwi", ENABLED, contextA));

		ActionsModel model = buildModel(contextA, ActionDisplayLevel.ALL);
		ActionChooserDialog dialog = getSwing(() -> new ActionChooserDialog(model));

		assertEquals(4, model.getSize());

		setFilterText(dialog, "Ctrl-1");

		assertEquals(1, model.getSize());
		assertEquals(Arrays.asList("Kiwi"), getDisplayedActionNames(model));

		setFilterText(dialog, "");
		assertEquals(4, model.getSize());
	}

	@Test
	public void testActivatingAction() {
		DockingActionIf appleAction = toolbar("Apple", ENABLED, contextA);
		addLocal(appleAction);
		addLocal(menuItem("Banana", ENABLED, contextA));
		addLocal(popup("Pear", ENABLED, ADD_TO_POPUP, contextA));
		addLocal(keyAction("Kiwi", ENABLED, contextA));

		ActionsModel model = buildModel(contextA, ActionDisplayLevel.ALL);
		ActionChooserDialog dialog = getSwing(() -> new ActionChooserDialog(model));
		dialog.selectAction(appleAction);

		assertEquals(0, triggeredActions.size());

		pressReturn(dialog);

		assertEquals(1, triggeredActions.size());
		assertEquals("Apple", triggeredActions.get(0));
	}

	private void pressReturn(ActionChooserDialog dialog) {
		runSwing(() -> dialog.okCallback());

		// simulate focus changed callback
		runSwing(() -> dialog.getActionRunner().propertyChange(null));
		waitForSwing();
	}

	private List<String> getDisplayedActionNames(ActionsModel model) {
		List<String> names = new ArrayList<>();
		List<SearchListEntry<DockingActionIf>> allItems = model.getDisplayedItems();
		for (SearchListEntry<DockingActionIf> entry : allItems) {
			names.add(entry.value().getName());
		}
		return names;
	}

	private void setFilterText(ActionChooserDialog dialog, String string) {
		runSwing(() -> dialog.setFilterText(string));
	}

	private List<String> getActionsForCategory(ActionsModel model, ActionGroup group) {
		List<String> names = new ArrayList<>();
		List<SearchListEntry<DockingActionIf>> allItems = model.getAllItems();
		for (SearchListEntry<DockingActionIf> entry : allItems) {
			if (entry.category().equals(group.getDisplayName())) {
				names.add(entry.value().getName());
			}
		}
		return names;
	}

	private void assertModelContains(ActionsModel model, String... actionNames) {
		List<SearchListEntry<DockingActionIf>> items = model.getDisplayedItems();
		Set<String> displayedActionNames =
			items.stream().map(x -> x.value().getName()).collect(Collectors.toSet());

		for (String actionName : actionNames) {
			if (!displayedActionNames.contains(actionName)) {
				fail("Displayed actions don't contain action \"" + actionName + "\"");
			}
		}
	}

	private ActionsModel buildModel(TestContextA context, ActionDisplayLevel displayLevel) {
		ActionsModel actionsModel = new ActionsModel(localActions, globalActions, context);
		actionsModel.setDisplayLevel(displayLevel);
		return actionsModel;
	}

	private void addLocal(DockingActionIf action) {
		localActions.add(action);
	}

	private void addGlobal(DockingActionIf action) {
		globalActions.add(action);
	}

	private DockingActionIf menuItem(String name, boolean enabled, ActionContext context) {
		return new ActionBuilder(name, "Test")
				.menuPath("menu", name)
				.withContext(context.getClass())
				.enabledWhen(c -> enabled)
				.onAction(e -> triggeredActions.add(name))
				.build();
	}

	private DockingActionIf popup(String name, boolean enabled, boolean addToPopup,
			ActionContext context) {
		return new ActionBuilder(name, "Test")
				.popupMenuPath(name)
				.withContext(context.getClass())
				.enabledWhen(c -> enabled)
				.popupWhen(c -> addToPopup)
				.onAction(e -> triggeredActions.add(name))
				.build();
	}

	private DockingActionIf keyAction(String name, boolean enabled, ActionContext context) {
		return new ActionBuilder(name, "Test")
				.keyBinding("CTRL 1")
				.withContext(context.getClass())
				.enabledWhen(c -> enabled)
				.onAction(e -> triggeredActions.add(name))
				.build();
	}

	private DockingActionIf toolbar(String name, boolean enabled, ActionContext context) {
		return new ActionBuilder(name, "Test")
				.toolBarIcon(Icons.ADD_ICON)
				.withContext(context.getClass())
				.enabledWhen(c -> enabled)
				.onAction(e -> triggeredActions.add(name))
				.build();
	}

	private class TestContextA extends DefaultActionContext {
		// just need different context class
	}

	private class TestContextB extends DefaultActionContext {
		// just need different context class
	}
}
