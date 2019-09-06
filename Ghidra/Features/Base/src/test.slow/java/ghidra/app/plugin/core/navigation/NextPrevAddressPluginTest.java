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

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

import javax.swing.*;

import org.junit.*;

import docking.*;
import docking.action.*;
import docking.menu.*;
import generic.test.TestUtils;
import ghidra.app.nav.LocationMemento;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.util.navigation.GoToAddressLabelDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;

public class NextPrevAddressPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program baseProgram;
	private PluginTool tool;

	private MultiActionDockingAction previousAction;
	private MultiActionDockingAction nextAction;
	private GoToAddressLabelDialog dialog;
	private CodeBrowserPlugin codeBrowserPlugin;
	private CodeViewerProvider provider;
	private AddressFactory addressFactory;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		baseProgram = builder.getProgram();

		addressFactory = baseProgram.getAddressFactory();
		tool = env.launchDefaultTool(baseProgram);
		builder.dispose();

		NextPrevAddressPlugin plugin = env.getPlugin(NextPrevAddressPlugin.class);
		previousAction =
			(MultiActionDockingAction) TestUtils.getInstanceField("previousAction", plugin);
		nextAction = (MultiActionDockingAction) TestUtils.getInstanceField("nextAction", plugin);

		GoToAddressLabelPlugin goToPlugin = env.getPlugin(GoToAddressLabelPlugin.class);
		dialog = goToPlugin.getDialog();

		codeBrowserPlugin = env.getPlugin(CodeBrowserPlugin.class);
		provider = codeBrowserPlugin.getProvider();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testBackwardAndForward() throws Exception {
		// disabled by default
		assertTrue(!nextAction.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(!previousAction.isEnabledForContext(provider.getActionContext(null)));

		// perform a goto
		Address startAddress = codeBrowserPlugin.getCurrentAddress();
		goTo("010018a0");
		codeBrowserPlugin.updateNow();
		waitForPostedSwingRunnables();

		// go backward generically
		backwardByAction();
		codeBrowserPlugin.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(startAddress, codeBrowserPlugin.getCurrentAddress());

		// go forward generically
		forwardByAction();
		codeBrowserPlugin.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(addr("0x010018a0"), codeBrowserPlugin.getCurrentAddress());

		// go backward from the dropdown
		backwardByDropdown();
		codeBrowserPlugin.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(startAddress, codeBrowserPlugin.getCurrentAddress());

		// go forward from the dropdown
		forwardByDrowdown();
		codeBrowserPlugin.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(addr("0x010018a0"), codeBrowserPlugin.getCurrentAddress());
	}

	@Test
	public void testNavigationFromMiddleOfPulldownAction() throws Exception {
		List<Symbol> navigatedSymbols = doBulkGoTo();
		Collections.reverse(navigatedSymbols); // the list was in reverse stack order, so fix it

		// the front of the list will not be on the navigation stack, since it is the current address
		Symbol bulkNavigationSymbol = navigatedSymbols.remove(0);

		// the previous list of actions should be the size of the list - 1
		List<DockingActionIf> actionList =
			previousAction.getActionList(provider.getActionContext(null));

		// verify the size...
		// (the navigated symbols plus the original location before we started)
		assertEquals(actionList.size(), navigatedSymbols.size() + 1);

		// ...verify the order
		int n = actionList.size() - 1; // don't compare the first location
		for (int i = 0; i < n; i++) {
			DockingActionIf dockableAction = actionList.get(i);
			LocationMemento location =
				(LocationMemento) getInstanceField("location", dockableAction);

			// start one off, because of the initial location in the browser to which we did not navigate
			Symbol symbol = navigatedSymbols.get(i);

			ProgramLocation loc = location.getProgramLocation();
			assertEquals("Location does not match symbol address: " + loc + " / symbol: " + symbol,
				loc.getAddress(), symbol.getAddress());
		}

		// pick one of the items in the list and go back to that item...
		int navigatedIndex = 4;
		DockingActionIf action = actionList.get(navigatedIndex);
		Symbol navigatedSymbol = navigatedSymbols.get(navigatedIndex);
		performAction(action, true);

		assertEquals(navigatedSymbol.getAddress(), codeBrowserPlugin.getCurrentAddress());

		// ...make sure the 'previous' list is updated with only actions after the one in our list
		actionList = previousAction.getActionList(provider.getActionContext(null));
		n = actionList.size() - 1; // don't compare the first location
		int navigatedIndexOffset = (navigatedIndex + 1); // don't count the navigated index
		int remainingSymbols = navigatedSymbols.size() - navigatedIndexOffset;
		assertEquals(n, remainingSymbols);
		for (int i = 0; i < n; i++) {
			DockingActionIf dockableAction = actionList.get(i);
			LocationMemento location =
				(LocationMemento) getInstanceField("location", dockableAction);

			// start one off, because of the initial location in the browser to which we did not navigate
			int offsetIndex = navigatedIndexOffset + i;
			Symbol symbol = navigatedSymbols.get(offsetIndex);
			assertEquals("Did not find expected navigation item at index: " + i,
				location.getProgramLocation().getAddress(), symbol.getAddress());
		}

		// ...make sure the next list is updated with the correct items from after that position
		// in the list
		actionList = nextAction.getActionList(provider.getActionContext(null));

		List<Symbol> nextNavigatedSymbols = subList(navigatedSymbols, 0, navigatedIndex);
		nextNavigatedSymbols.add(0, bulkNavigationSymbol); // put on the original location from the bulk navigation
		Collections.reverse(nextNavigatedSymbols); // the 'next' list is not reversed, like the 'previous' list is
		assertEquals(actionList.size(), nextNavigatedSymbols.size());

		for (int i = 0; i < actionList.size(); i++) {
			DockingActionIf dockableAction = actionList.get(i);
			LocationMemento location =
				(LocationMemento) getInstanceField("location", dockableAction);
			Symbol symbol = nextNavigatedSymbols.get(i);
			assertEquals(location.getProgramLocation().getAddress(), symbol.getAddress());
		}

		// pick one of the items in the next list and go to that item...        
		DockingActionIf navigatedAction = actionList.get(2);
		LocationMemento navigatedLocation =
			(LocationMemento) getInstanceField("location", navigatedAction);
		navigatedSymbol =
			findSymbolForLocation(navigatedSymbols, navigatedLocation.getProgramLocation());
		navigatedIndex = navigatedSymbols.indexOf(navigatedSymbol);

		performAction(navigatedAction, true);

		assertEquals(navigatedSymbol.getAddress(), codeBrowserPlugin.getCurrentAddress());

		// ...make sure that the 'previous' list is properly updated
		actionList = previousAction.getActionList(provider.getActionContext(null));
		n = actionList.size() - 1; // don't compare the first location
		navigatedIndexOffset = (navigatedIndex + 1); // don't count the navigated index
		remainingSymbols = navigatedSymbols.size() - navigatedIndexOffset;
		assertEquals(n, remainingSymbols);
		for (int i = 0; i < n; i++) {
			DockingActionIf dockableAction = actionList.get(i);
			LocationMemento location =
				(LocationMemento) getInstanceField("location", dockableAction);

			// start one off, because of the initial location in the browser to which we did not navigate
			int offsetIndex = navigatedIndexOffset + i;
			Symbol symbol = navigatedSymbols.get(offsetIndex);
			assertEquals("Did not find expected navigation item at index: " + i,
				location.getProgramLocation().getAddress(), symbol.getAddress());
		}

		// ...make sure the 'next' list is properly updated
		actionList = nextAction.getActionList(provider.getActionContext(null));

		nextNavigatedSymbols = subList(navigatedSymbols, 0, navigatedIndex);
		nextNavigatedSymbols.add(0, bulkNavigationSymbol); // put on the original location from the bulk navigation
		Collections.reverse(nextNavigatedSymbols); // the 'next' list is not reversed, like the 'previous' list is
		assertEquals(actionList.size(), nextNavigatedSymbols.size());

		for (int i = 0; i < actionList.size(); i++) {
			DockingActionIf dockableAction = actionList.get(i);
			LocationMemento location =
				(LocationMemento) getInstanceField("location", dockableAction);
			Symbol symbol = nextNavigatedSymbols.get(i);
			assertEquals(location.getProgramLocation().getAddress(), symbol.getAddress());
		}
	}

	private Symbol findSymbolForLocation(List<Symbol> navigatedSymbols, ProgramLocation location) {
		for (Symbol symbol : navigatedSymbols) {
			if (symbol.getAddress().equals(location.getAddress())) {
				return symbol;
			}
		}
		return null;
	}

	// didn't use List.subList for debugging
	private List<Symbol> subList(List<Symbol> list, int start, int end) {
		List<Symbol> newList = new ArrayList<>();
		for (int i = start; i < end; i++) {
			newList.add(list.get(i));
		}
		return newList;
	}

	private Address addr(String address) {
		return addressFactory.getAddress(address);
	}

	private void goTo(String locationName) throws Exception {
		setText(locationName);
		performOkCallback();
	}

	private void forwardByAction() {
		assertTrue(nextAction.isEnabled());
		performAction(nextAction, true);
	}

	private void backwardByAction() {
		assertTrue(previousAction.isEnabled());
		performAction(previousAction, true);
	}

	private void backwardByDropdown() {
		assertTrue(previousAction.isEnabled());
		JFrame toolFrame = tool.getToolFrame();
		DockingWindowManager dwm = DockingWindowManager.getInstance(toolFrame);
		JButton previousButton = findButtonForAction(dwm, previousAction);
		clickDropdownForButton(previousButton);
	}

	private void forwardByDrowdown() {
		assertTrue(nextAction.isEnabled());
		JFrame toolFrame = tool.getToolFrame();
		DockingWindowManager dwm = DockingWindowManager.getInstance(toolFrame);
		JButton nextButton = findButtonForAction(dwm, nextAction);
		clickDropdownForButton(nextButton);
	}

	private void clickDropdownForButton(JButton button) {

		//
		// Unusual Code Alert: we change the state of the button directly.  The button is an
		// instance of MultipleActionDockingToolbarButton, which has a popup menu.  We wish
		// to press one of the buttons in the menu.  Since the popup is sensitive to application
		// focus, we cannot rely on the menu being there when we need it.  So, we will reach
		// into the button and set/get the state as we need it.
		//

		// clear the popup
		Object mouseAdapter = getInstanceField("popupListener", button);
		setInstanceField("popupMenu", mouseAdapter, null);

		// trigger the popup
		Shape popupTriggerArea = (Shape) TestUtils.getInstanceField("popupContext", button);
		Rectangle clickableBounds = popupTriggerArea.getBounds();
		int x = clickableBounds.x + (clickableBounds.width / 2);
		int y = clickableBounds.y + (clickableBounds.height / 2);
		clickMouse(button, MouseEvent.BUTTON1, x, y, 1, 0);

		// get the popup
		JPopupMenu menu = (JPopupMenu) getInstanceField("popupMenu", mouseAdapter);
		assertNotNull(menu);

		// Note: calling clickMouse() seems to work for now.  If this is not consistent, then
		//       we can reach into the menu item and fire it directly.
		Component component = menu.getComponent(0);
		assertTrue((component instanceof JMenuItem));
		Rectangle bounds = component.getBounds();
		x = bounds.x + (bounds.width / 2);
		y = bounds.y + (bounds.height / 2);
		clickMouse(component, MouseEvent.BUTTON1, x, y, 1, 0);
	}

	@SuppressWarnings("unchecked")
	// let caution fly
	private JButton findButtonForAction(DockingWindowManager windowManager, DockingAction action) {
		Object actionToGuiMapper = TestUtils.getInstanceField("actionToGuiMapper", windowManager);
		Object menuAndToolBarManager =
			TestUtils.getInstanceField("menuAndToolBarManager", actionToGuiMapper);
		Map<WindowNode, WindowActionManager> map =
			(Map<WindowNode, WindowActionManager>) TestUtils.getInstanceField(
				"windowToActionManagerMap", menuAndToolBarManager);
		Iterator<WindowActionManager> iterator = map.values().iterator();

		while (iterator.hasNext()) {
			WindowActionManager wam = iterator.next();
			ToolBarManager toolBarManager =
				(ToolBarManager) TestUtils.getInstanceField("toolBarMgr", wam);

			Map<String, List<ToolBarItemManager>> groupToItemsMap =
				(Map<String, List<ToolBarItemManager>>) TestUtils.getInstanceField(
					"groupToItemsMap", toolBarManager);

			ToolBarData toolBarData = action.getToolBarData();
			String group = toolBarData.getToolBarGroup();
			List<ToolBarItemManager> items = groupToItemsMap.get(group);
			if (items == null) {
				continue;
			}

			for (ToolBarItemManager item : items) {
				DockingActionProxy proxy = (DockingActionProxy) item.getAction();
				if (proxy.getAction() == action) {
					return item.getButton();
				}
			}
		}

		Assert.fail("Unable to locate button for action: " + action.getName());
		return null; // can't get here, but the compiler doesn't know that
	}

	private List<Symbol> doBulkGoTo() throws Exception {
		List<Symbol> list = new ArrayList<>();
		Memory memory = baseProgram.getMemory();
		int count = 0;
		SymbolIterator iter = baseProgram.getSymbolTable().getAllSymbols(true);
		while (iter.hasNext() && count < 11) {
			Symbol symbol = iter.next();
			Address addr = symbol.getAddress();
			if ((addr.isMemoryAddress() && !memory.contains(addr)) || addr.isExternalAddress()) {
				continue;
			}
			list.add(symbol);
			setText(symbol.getName());
			performOkCallback();
			++count;
		}
		return list;
	}

	private void setText(final String text) throws Exception {
		SwingUtilities.invokeAndWait(() -> dialog.setText(text));
	}

	private void performOkCallback() throws Exception {
		runSwing(() -> dialog.okCallback());
		waitForPostedSwingRunnables();
	}
}
