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
package ghidra.app.plugin.core.byteviewer;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.*;
import java.util.List;

import javax.swing.JLabel;

import org.junit.After;
import org.junit.Before;

import docking.*;
import docking.action.*;
import docking.menu.ToolBarItemManager;
import docking.menu.ToolBarManager;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.field.SimpleTextField;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.format.*;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public abstract class AbstractByteViewerPluginTest extends AbstractGhidraHeadedIntegrationTest {

	protected TestEnv env;
	protected PluginTool tool;
	protected Program program;
	protected ByteViewerPlugin plugin;
	protected ByteViewerPanel panel;
	protected CodeBrowserPlugin cbPlugin;
	protected ProgramByteViewerComponentProvider provider;
	protected Memory memory;
	protected Listing listing;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.showTool();
		for (Class<? extends Plugin> pluginClass : getDefaultPlugins()) {
			tool.addPlugin(pluginClass.getName());
		}
		tool.addPlugin(ByteViewerPlugin.class.getName());

		plugin = env.getPlugin(ByteViewerPlugin.class);
		provider = plugin.getProvider();
		panel = provider.getByteViewerPanel();

		tool.showComponentProvider(provider, true);
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		program = buildProgram();
		memory = program.getMemory();
		listing = program.getListing();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	abstract protected List<Class<? extends Plugin>> getDefaultPlugins();

	abstract protected Program buildProgram() throws Exception;

	protected void assertPosition(ByteViewerComponent view, String expectedFieldText,
			int expectedColumn) {

		String fieldText = runSwing(() -> {
			Field field = view.getCurrentField();
			String text = field.getText();
			return text;
		});
		assertEquals(expectedFieldText, fieldText);

		FieldLocation location = runSwing(() -> view.getCursorLocation());
		assertEquals(expectedColumn, location.getCol());
	}

	protected void setEditMode(boolean b) {
		ToggleDockingAction action = provider.getEditModeAction();
		if (action.isSelected() != b) {
			performAction(action);
			assertTrue(action.isSelected() == b);
		}
	}

	protected void gotoInPanel(Address addr) {
		runSwing(() -> {
			ProgramByteBlockSet blockset = (ProgramByteBlockSet) provider.getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(addr);
			panel.setCursorLocation(bbInfo.getBlock(), bbInfo.getOffset(), bbInfo.getColumn());
		});
	}

	protected void goTo(Address addr) {
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, addr));
	}

	protected void goToByte(String addr) {
		goToByte(addr(addr));
	}

	protected void goToByte(Address addr) {
		ByteViewerComponent view = runSwing(() -> panel.getCurrentComponent());
		goToByte(view, addr);
	}

	protected void goToByte(ByteViewerComponent view, Address addr) {
		FieldLocation loc = getFieldLocation(addr);
		runSwing(() -> {
			view.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});
	}

	protected void setByteViewerLocation(Address address) throws Exception {
		setByteViewerLocation(provider, address);
	}

	protected void setByteViewerLocation(ProgramByteViewerComponentProvider testProvider,
			Address address) throws Exception {
		ByteViewerPanel byteViewerPanel = testProvider.getByteViewerPanel();
		ByteViewerComponent component = byteViewerPanel.getCurrentComponent();
		FieldLocation byteViewerLocation = getFieldLocation(address);

		runSwing(() -> {
			component.setCursorPosition(byteViewerLocation.getIndex(),
				byteViewerLocation.getFieldNum(), byteViewerLocation.getRow(),
				byteViewerLocation.getCol());
			component.scrollToCursor();
		});
	}

	protected void setViewSelected(ByteViewerOptionsDialog dialog, String viewName,
			boolean selected) {
		runSwing(() -> dialog.setModelSelected(viewName, selected));
	}

	protected ByteViewerOptionsDialog launchByteViewerOptions() {
		DockingAction action = provider.getOptionsAction();
		assertTrue(action.isEnabled());

		runSwing(() -> action.actionPerformed(new DefaultActionContext()), false);
		waitForSwing();
		ByteViewerOptionsDialog d = waitForDialogComponent(ByteViewerOptionsDialog.class);
		return d;
	}

	protected ByteViewerComponent setView(String name) {
		ByteViewerComponent view = getView(name);
		setView(view);
		return view;
	}

	protected void setView(ByteViewerComponent view) {
		runSwing(() -> panel.setCurrentView(view));
	}

	protected ByteViewerComponent getView(String name) {
		ByteViewerComponent c = runSwing(() -> panel.getComponentByName(name));
		if (c == null) {
			fail("Cannot find view '" + name + "'");
		}
		return c;
	}

	protected ByteViewerComponent getCurrentView() {
		return panel.getCurrentComponent();
	}

	protected ByteField getField(String viewName, Address addr) {
		return runSwing(() -> {
			ByteViewerComponent c = panel.getComponentByName(viewName);
			ProgramByteBlockSet blockset = (ProgramByteBlockSet) provider.getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(addr);
			FieldLocation loc = c.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());
			return c.getField(loc.getIndex(), loc.getFieldNum());
		});
	}

	protected ByteField getField(ByteViewerComponent c) {
		return runSwing(() -> {
			FieldLocation loc = c.getCursorLocation();
			return c.getField(loc.getIndex(), loc.getFieldNum());
		});
	}

	protected ByteField getField(ByteViewerComponent c, Address addr) {
		return runSwing(() -> {
			ProgramByteBlockSet blockset = (ProgramByteBlockSet) provider.getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(addr);
			FieldLocation loc = c.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());
			return c.getField(loc.getIndex(), loc.getFieldNum());
		});
	}

	protected FieldLocation getFieldLocation(Address addr) {
		return runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			ProgramByteBlockSet blockset = (ProgramByteBlockSet) provider.getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(addr);
			return c.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());
		});
	}

	protected FieldLocation getFieldLocation(ByteViewerComponent c, Address addr) {
		return runSwing(() -> {
			ProgramByteBlockSet blockset = (ProgramByteBlockSet) provider.getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(addr);
			return c.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());
		});
	}

	protected Address addr(long offset) {
		return program.getImageBase().getNewAddress(offset);
	}

	protected Address addr(String offset) {
		return program.getAddressFactory().getAddress(offset);
	}

	protected Address convertToAddr(ByteBlockInfo info) {
		return ((ProgramByteBlockSet) provider.getByteBlockSet()).getAddress(info.getBlock(),
			info.getOffset());
	}

	protected boolean byteBlockSelectionEquals(ByteBlockSelection b1, ByteBlockSelection b2) {

		int nRanges = b1.getNumberOfRanges();
		if (nRanges != b2.getNumberOfRanges()) {
			return false;
		}
		for (int i = 0; i < nRanges; i++) {
			ByteBlockRange range1 = b1.getRange(i);
			ByteBlockRange range2 = b2.getRange(i);
			if (!range1.equals(range2)) {
				return false;
			}
		}
		return true;
	}

	protected ByteViewerComponent findComponent(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof ByteViewerComponent) {
				if (((ByteViewerComponent) element).getDataModel().getName().equals(name)) {
					return (ByteViewerComponent) element;
				}
			}
			else if (element instanceof Container) {
				ByteViewerComponent bvc = findComponent((Container) element, name);
				if (bvc != null) {
					return bvc;
				}
			}
		}
		return null;
	}

	protected void loadViews(String... viewNames) {
		enableViews(true, viewNames);
	}

	protected void enableViews(boolean b, String... viewNames) {
		assertNotEquals(0, viewNames.length);
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		for (String name : viewNames) {
			setViewSelected(dialog, name, b);
		}
		pressButtonByText(dialog.getComponent(), "OK");
	}

	protected Container findContainer(Container parent, Class<?> theClass) {
		Component[] c = parent.getComponents();
		for (Component element : c) {
			if (element.getClass() == theClass) {
				return (Container) element;
			}
			if (element instanceof Container) {
				Container container = findContainer((Container) element, theClass);
				if (container != null) {
					return container;
				}
			}
		}
		return null;
	}

	protected String findLabelStr(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof JLabel) {
				if (name.equals(element.getName())) {
					return ((JLabel) element).getText();
				}
			}
			if (element instanceof Container) {
				String str = findLabelStr((Container) element, name);
				if (str != null) {
					return str;
				}
			}
		}
		return null;
	}

	protected void setViewWidth(String name, int width) {
		runSwing(() -> {
			panel.setViewWidth(name, width);
		});
	}

	protected int getViewWidth(String name) {
		return runSwing(() -> {
			return panel.getViewWidth(name);
		});
	}

	protected void goTo(Address a, String fieldName) {
		int row = 0;
		int col = 0;
		assertTrue(cbPlugin.goToField(a, fieldName, row, col));
	}

	protected void leftArrow() {
		runSwing(() -> {
			ByteViewerComponent view = panel.getCurrentComponent();
			view.cursorLeft();
		});
	}

	protected void rightArrow() {

		runSwing(() -> {
			ByteViewerComponent view = panel.getCurrentComponent();
			view.cursorRight();
		});
	}

	protected void pressKey(int modifiers, int keyCode, char keyChar) {
		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), modifiers, keyCode, keyChar);
			FieldLocation loc = c.getCursorLocation();
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
	}

	protected void assertByteData(Address addr, int byteValue) throws MemoryAccessException {
		byte b = memory.getByte(addr);
		assertEquals(byteValue, Byte.toUnsignedInt(b));
	}

	protected void assertOffsetInfo(int offset, String addr) {
		assertEquals(offset, runSwing(() -> provider.getConfigOptions().getOffset()).intValue());
		assertEquals(Integer.toString(offset), findLabelStr(provider.getComponent(), "Offset"));
		assertEquals(addr, findLabelStr(provider.getComponent(), "Insertion"));
	}

	protected void assertFieldLocationInfo(String addr, int index, int fieldNum) {
		assertFieldLocationInfo(addr(addr), index, fieldNum);
	}

	protected void assertFieldLocationInfo(Address addr, int index, int fieldNum) {
		FieldLocation floc = getFieldLocation(addr);
		assertEquals(index, floc.getIndex().intValue());
		assertEquals(fieldNum, floc.getFieldNum());
	}

	@SuppressWarnings("unchecked")
	protected void assertOnlyOneProviderToolbarAction() {

		DockingWindowManager dwm = tool.getWindowManager();
		ActionToGuiMapper guiActions =
			(ActionToGuiMapper) getInstanceField("actionToGuiMapper", dwm);
		GlobalMenuAndToolBarManager menuManager =
			(GlobalMenuAndToolBarManager) getInstanceField("menuAndToolBarManager", guiActions);

		Map<WindowNode, WindowActionManager> windowToActionManagerMap =
			(Map<WindowNode, WindowActionManager>) getInstanceField("windowToActionManagerMap",
				menuManager);

		DockingActionIf showAction =
			(DockingActionIf) getInstanceField("showProviderAction", provider);
		String actionName = showAction.getName();
		List<DockingActionIf> matches = new ArrayList<>();
		for (WindowActionManager actionManager : windowToActionManagerMap.values()) {

			ToolBarManager toolbarManager =
				(ToolBarManager) getInstanceField("toolBarMgr", actionManager);
			Map<String, List<ToolBarItemManager>> groupToItems =
				(Map<String, List<ToolBarItemManager>>) getInstanceField("groupToItemsMap",
					toolbarManager);

			Collection<List<ToolBarItemManager>> values = groupToItems.values();
			for (List<ToolBarItemManager> list : values) {
				for (ToolBarItemManager manager : list) {
					DockingActionIf action = manager.getAction();
					if (actionName.equals(action.getName())) {
						matches.add(action);
					}
				}
			}
		}

		assertEquals("Should only have 1 action on toolbar to show the provider", 1,
			matches.size());
	}

	protected void goToOperand(String addr) {
		goTo(addr(addr), OperandFieldFactory.FIELD_NAME);
	}

	protected void rightArrowListing() {
		FieldPanel fp = cbPlugin.getFieldPanel();
		runSwing(() -> fp.cursorRight());
	}

	protected void leftArrowListing() {
		FieldPanel fp = cbPlugin.getFieldPanel();
		runSwing(() -> fp.cursorLeft());
	}

	protected void assertListingPosition(String expectedFieldText, int expectedColumn) {
		FieldPanel fp = cbPlugin.getFieldPanel();

		String fieldText = runSwing(() -> {
			Field field = fp.getCurrentField();
			String text = field.getText();
			return text;
		});
		assertEquals(expectedFieldText, fieldText);

		FieldLocation location = runSwing(() -> fp.getCursorLocation());
		assertEquals(expectedColumn, location.getCol());
	}

	protected void assertFieldColor(FieldLocation loc, Color expectedColor) {
		assertFieldColor(loc, expectedColor, false);
	}

	protected void assertFieldColor(FieldLocation loc, Color expectedColor, boolean allowNull) {
		ByteViewerComponent c = panel.getCurrentComponent();
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertFieldColor(field, expectedColor, allowNull);
	}

	protected void assertFieldColor(SimpleTextField field, Color expectedColor) {
		assertFieldColor(field, expectedColor, false);
	}

	protected void assertFieldColor(SimpleTextField field, Color expectedColor, boolean allowNull) {
		Color c = field.getForeground();
		if (c == null && expectedColor != null) {
			if (allowNull) {
				return;
			}
			fail("Field had no color: " + field);
		}
		assertEquals(expectedColor, c);
	}

	protected void assertColor(Color expectedColor, Color actualColor) {
		assertColor(expectedColor, actualColor, false);
	}

	protected void assertColor(Color expectedColor, Color actualColor, boolean allowNull) {
		if (actualColor == null && expectedColor != null) {
			if (allowNull) {
				return;
			}
			fail("Color was null, expected " + expectedColor);
		}
		assertEquals(expectedColor, actualColor);
	}

	protected void assertCursorColor(ByteViewerComponent c, Color expectedColor) {
		assertColor(expectedColor, c.getFocusedCursorColor());

	}

}
