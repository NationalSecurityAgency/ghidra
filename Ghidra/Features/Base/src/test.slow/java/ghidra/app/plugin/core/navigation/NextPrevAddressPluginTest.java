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
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;

public class NextPrevAddressPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private PluginTool tool;

	private MultiActionDockingAction previousAction;
	private MultiActionDockingAction nextAction;
	private DockingAction previousFunctionAction;
	private DockingAction nextFunctionAction;
	private CodeBrowserPlugin cbPlugin;
	private CodeViewerProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();

		tool = env.launchDefaultTool(program);
		builder.dispose();

		NextPrevAddressPlugin plugin = env.getPlugin(NextPrevAddressPlugin.class);
		previousAction = plugin.getPreviousAction();
		nextAction = plugin.getNextAction();
		previousFunctionAction = plugin.getPreviousFunctionAction();
		nextFunctionAction = plugin.getNextFunctionAction();

		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		provider = cbPlugin.getProvider();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testNavigationFromMiddleOfPulldownAction() throws Exception {
		List<Symbol> navigatedSymbols = doBulkGoTo();
		Collections.reverse(navigatedSymbols); // the list was in reverse stack order, so fix it

		// the front of the list will not be on the navigation stack, since it is the current address
		Symbol bulkNavigationSymbol = navigatedSymbols.remove(0);

		// the previous list of actions should be the size of the list - 1
		List<DockingActionIf> actionList =
			previousAction.getActionList(getContext());

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

		assertEquals(navigatedSymbol.getAddress(), currentAddress());

		// ...make sure the 'previous' list is updated with only actions after the one in our list
		actionList = previousAction.getActionList(getContext());
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
		actionList = nextAction.getActionList(getContext());

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

		assertEquals(navigatedSymbol.getAddress(), currentAddress());

		// ...make sure that the 'previous' list is properly updated
		actionList = previousAction.getActionList(getContext());
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
		actionList = nextAction.getActionList(getContext());

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

	@Test
	public void testBackwardAndForward() throws Exception {
		// disabled by default; no history
		assertFalse(nextAction.isEnabledForContext(getContext()));
		assertFalse(previousAction.isEnabledForContext(getContext()));

		Address startAddress = currentAddress();
		Address secondAddress = addr("010018a0");
		goTo(secondAddress);

		previous();
		assertCurrentAddress(startAddress);

		next();
		assertCurrentAddress(secondAddress);

		// try the drop-down popup
		previousByDropdown();
		assertCurrentAddress(startAddress);

		nextByDrowdown();
		assertCurrentAddress(secondAddress);
	}

	@Test
	public void testFunctionNavigation_OnlyFunctionsInHistory() throws Exception {
		Address f1 = addr("01002cf5"); // ghidra
		Address f2 = addr("01006420"); // entry
		Address f3 = addr("0100415a"); // sscanf 

		assertDisabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);
		goTo(f1);
		assertDisabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);

		goTo(f2);
		assertEnabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);

		goTo(f3);
		assertEnabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);

		previousFunction();
		assertCurrentAddress(f2);
		assertEnabled(previousFunctionAction);
		assertEnabled(nextFunctionAction);

		previousFunction();
		assertCurrentAddress(f1);
		assertDisabled(previousFunctionAction);
		assertEnabled(nextFunctionAction);

		nextFunction();
		assertCurrentAddress(f2);
		assertEnabled(previousFunctionAction);
		assertEnabled(nextFunctionAction);
	}

	@Test
	public void testFunctionNavigation_MixedHistory() throws Exception {
		Address f1 = addr("01002cf5"); // ghidra
		Address a1 = f1.add(1);
		Address a2 = f1.add(3);
		Address a3 = f1.add(8);
		Address f2 = addr("01006420"); // entry

		assertDisabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);
		goTo(f1);
		assertDisabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);

		goTo(a1);
		assertDisabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);
		goTo(a2);
		goTo(a3);
		assertDisabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);

		// new function
		goTo(f2);
		assertEnabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);

		previousFunction();
		assertCurrentAddress(a3); // last location in a different function
		assertDisabled(previousFunctionAction);
		assertEnabled(nextFunctionAction);

		nextFunction();
		assertCurrentAddress(f2);
		assertEnabled(previousFunctionAction);
		assertDisabled(nextFunctionAction);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private ComponentProvider showDecompiler() {
		ComponentProvider cp = tool.getComponentProvider("Decompiler");
		tool.showComponentProvider(cp, true);
		cp.requestFocus();
		return cp;
	}

	private void assertCurrentAddress(Address expected) {
		assertEquals(expected, currentAddress());
	}

	private void assertEnabled(DockingAction action) {
		assertTrue("Action should have been enabled: " + action.getName(),
			action.isEnabledForContext(getContext()));
	}

	private void assertDisabled(DockingAction action) {
		assertFalse("Action should have been disabled: " + action.getName(),
			action.isEnabledForContext(getContext()));
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
		return program.getAddressFactory().getAddress(address);
	}

	private void goTo(Symbol s) throws Exception {
		goTo(s.getAddress());
	}

	private void goTo(Address a) throws Exception {
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(a);
		cbPlugin.updateNow();
		waitForSwing();
	}

	private void next() {
		assertTrue(nextAction.isEnabledForContext(getContext()));
		performAction(nextAction, true);
		cbPlugin.updateNow();
		waitForSwing();
	}

	private void previous() {
		assertTrue(previousAction.isEnabledForContext(getContext()));
		performAction(previousAction, true);
		cbPlugin.updateNow();
		waitForSwing();
	}

	private void previousFunction() {
		assertTrue(previousFunctionAction.isEnabledForContext(getContext()));
		performAction(previousFunctionAction, getContext(), true);
		cbPlugin.updateNow();
		waitForSwing();
	}

	private void nextFunction() {
		assertTrue(nextFunctionAction.isEnabledForContext(getContext()));
		performAction(nextFunctionAction, getContext(), true);
		cbPlugin.updateNow();
		waitForSwing();
	}

	private void previousByDropdown() {
		assertTrue(previousAction.isEnabledForContext(getContext()));
		JFrame toolFrame = tool.getToolFrame();
		DockingWindowManager dwm = DockingWindowManager.getInstance(toolFrame);
		JButton previousButton = findButtonForAction(dwm, previousAction);
		clickDropdownForButton(previousButton);
		waitForSwing();
	}

	private void nextByDrowdown() {
		assertTrue(nextAction.isEnabledForContext(getContext()));
		JFrame toolFrame = tool.getToolFrame();
		DockingWindowManager dwm = DockingWindowManager.getInstance(toolFrame);
		JButton nextButton = findButtonForAction(dwm, nextAction);
		clickDropdownForButton(nextButton);
		waitForSwing();
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
		Memory memory = program.getMemory();
		int count = 0;
		SymbolIterator iter = program.getSymbolTable().getAllSymbols(true);
		while (iter.hasNext() && count < 11) {
			Symbol symbol = iter.next();
			Address addr = symbol.getAddress();
			if ((addr.isMemoryAddress() && !memory.contains(addr)) || addr.isExternalAddress()) {
				continue;
			}
			list.add(symbol);
			goTo(symbol);
			++count;
		}
		return list;
	}

	private Address currentAddress() {
		return cbPlugin.getCurrentAddress();
	}

	private ActionContext getContext() {
		return provider.getActionContext(null);
	}
}
