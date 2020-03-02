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
package ghidra.app.plugin.core.colorizer;

import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Window;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.options.editor.GhidraColorChooser;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.navigation.NavigationOptions.RangeNavigationEnum;
import ghidra.app.services.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ColorizingPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private AddressFactory addrFactory;

	private CodeBrowserPlugin cb;
	private ColorizingPlugin colorizerPlugin;
	private ColorizingService colorizingService;
	private DockingActionIf clearColorAction;
	private DockingActionIf clearAllColorsAction;
	private DockingActionIf setColorAction;
	private DockingActionIf nextColorRangeAction;
	private DockingActionIf previousColorRangeAction;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(ColorizingPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());

		cb = env.getPlugin(CodeBrowserPlugin.class);
		colorizerPlugin = getPlugin(tool, ColorizingPlugin.class);
		colorizingService = colorizerPlugin.getColorizingService();

		clearColorAction = getAction(colorizerPlugin, "Clear Color");
		clearAllColorsAction = getAction(colorizerPlugin, "Clear All Colors");
		setColorAction = getAction(colorizerPlugin, "Set Color");
		nextColorRangeAction = getAction(colorizerPlugin, "Next Color Range");
		previousColorRangeAction = getAction(colorizerPlugin, "Previous Color Range");

		env.showTool();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		builder.createEncodedString("010036c6", "abcde", StandardCharsets.US_ASCII, false);
		builder.applyDataType("010036d5", new WordDataType(), 1);
		builder.createEncodedString("010036e0", "abcde", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("010036f5", "ab", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("01003703", "abcde", StandardCharsets.US_ASCII, false);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testSetColor() throws Exception {
		assertAllActionsDisabled();

		// 
		// set color with no selection
		//
		loadProgram("notepad");
		assertClearActionsEnabled(false);
		assertNavigationActionsEnabled(false);
		assertSetColorActionEnabled(true);

		Color color = Color.RED;
		setColor(color);
		assertColorForAddress(color);

		assertClearActionsEnabled(true);
		assertSetColorActionEnabled(true);

		// 
		// set color over a selection
		//
		createSelection();

		assertSetColorActionEnabled(true);

		Color selectionColor = Color.BLUE;
		setColor(selectionColor);
		assertColorForSelection(selectionColor);

		assertClearActionsEnabled(true);
		assertSetColorActionEnabled(true);
	}

	@Test
	public void testClearColor() throws Exception {
		//
		// Clear the current address
		//
		loadProgram("notepad");

		Address address1 = cb.getCurrentAddress();
		Address address2 = address1.add(8);
		Color color = Color.RED;
		setColor(color, address1, address2);
		assertColorForAddress(color, address1, address2);

		clearColor(address2);
		assertNoColorForAddress(address2);
		assertColorForAddress(color, address1); // make sure the last clear didn't clear the first color

		createSelection();

		Color selectionColor = Color.BLUE;
		setColor(selectionColor);
		assertColorForSelection(selectionColor);

		clearColor();
		assertNoColorForSelection(selectionColor);
	}

	@Test
	public void testClearAll() throws Exception {
		//
		// Make a few non-contiguous color changes then clear all and make sure they are gone
		//
		loadProgram("notepad");
		Address address1 = cb.getCurrentAddress();
		Address address2 = address1.add(8);
		Address address3 = address2.add(16);

		Color color = new Color(100, 100, 100, 100);
		setColor(color, address1, address2, address3);
		assertColorForAddress(color, address1, address2, address3);

		goTo(address2);
		clearAllColors();
		assertNoColorForAddress();

		// make sure the addresses the other address were cleared as well
		assertNoColorForAddress(address1);
		assertNoColorForAddress(address3);
	}

	@Test
	public void testMarkerServiceWhenSettingColorFromAPI() throws Exception {
		loadProgram("notepad");
		Address address = cb.getCurrentAddress();

		// change the location so that the current line marker does not affect our color check below
		address = address.add(400);
		Color color = new Color(100, 100, 100);
		setBackgroundFromAPI(address, color);

		assertMarkerColorAtAddress(address, color);
	}

	@Test
	public void testNavigateColorRanges() throws Exception {
		//
		// Apply some colors at non-contiguous addresses and make sure the navigation buttons 
		// appear and navigate as expected.
		//
		loadProgram("notepad");
		assertNavigationActionsEnabled(false);

		Address initialAddress = cb.getCurrentAddress();
		Address address1 = initialAddress.add(8);
		Address address2 = address1.add(8);
		Address address3 = address2.add(8);

		Color color = new Color(100, 100, 100, 100);
		setColor(color, address1, address2, address3);

		// start before the first address to test that the next range action is enabled and the
		// previous range action is not
		goTo(initialAddress);
		assertNextButtonEnabled(true);
		assertPreviousButtonEnabled(false);

		nextColor();							// go to 1st range
		assertNextButtonEnabled(true);
		assertPreviousButtonEnabled(false);

		nextColor();							// go to 2nd range
		assertNextButtonEnabled(true);
		assertPreviousButtonEnabled(true);

		nextColor();							// go to 3rd range
		assertNextButtonEnabled(false);
		assertPreviousButtonEnabled(true);

		previousColor();						// go back to 2nd range
		assertNextButtonEnabled(true);
		assertPreviousButtonEnabled(true);

		previousColor();                        // go back to 1st range
		assertNextButtonEnabled(true);
		assertPreviousButtonEnabled(false);

		// check the 'past the last range' boundary case
		Address farAndAway = address3.add(24);
		goTo(farAndAway);
		assertNextButtonEnabled(false);
		assertPreviousButtonEnabled(true);
	}

	/**
	 * Tests navigation of offcut ranges when coloring is set from a GUI/API point-of-view.
	 * @throws Exception 
	 */
	@Test
	public void testNavigateTopBottomOffcutColorRanges() throws Exception {
		// Apply colors that might end at offcut addresses and make sure navigation works as expected.
		loadProgram("notepad");
		assertNavigationActionsEnabled(false);

		Address initialAddress = cb.getCurrentAddress();	// 0x1001000
		Color selectionColor = Color.YELLOW;

		createSelectionBytes("0x10036c0", 0, 0, "0x10036c6", 1, 2);  // Sets offcut at end of range
		setColor(selectionColor);

		createSelectionBytes("0x10036d3", 0, 0, "0x10036d5", 0, 5);  // No offcuts
		setColor(selectionColor);

		createSelectionBytes("0x10036e0", 0, 2, "0x10036e6", 0, 2);  // Sets offcut at beginning of range
		setColor(selectionColor);

		createSelectionBytes("0x10036f5", 0, 6, "0x1003703", 1, 3);  // Sets offcut at both beginning and end of range
		setColor(selectionColor);

		createSelectionBytes("0x1003713", 0, 0, "0x1003723", 0, 2);  // No offcuts
		setColor(selectionColor);

		configureTopAndBottomRangeTraversal();

		goTo(initialAddress);

		// Verify addresses during forward traversal
		nextColor();							// go to beginning of 1st range
		assertEquals(cb.getCurrentAddress(), addr("0x10036c0"));

		nextColor();							// go to end of 1st range  (offcut here)
		assertEquals(cb.getCurrentAddress(), addr("0x10036c6"));

		nextColor();							// go to beginning of 2nd range
		assertEquals(cb.getCurrentAddress(), addr("0x10036d3"));

		nextColor();							// go to end of 2nd range
		assertEquals(cb.getCurrentAddress(), addr("0x10036d5"));

		nextColor();							// go to beginning of 3rd range (offcut here)
		assertEquals(cb.getCurrentAddress(), addr("0x10036e0"));

		nextColor();							// go to end of 3rd range
		assertEquals(cb.getCurrentAddress(), addr("0x10036e6"));

		nextColor();							// go to beginning of 4th range (offcut here)
		assertEquals(cb.getCurrentAddress(), addr("0x10036f5"));

		nextColor();							// go to end of 4th range (offcut here)
		assertEquals(cb.getCurrentAddress(), addr("0x1003703"));

		nextColor();							// go to beginning of 5th range
		assertEquals(cb.getCurrentAddress(), addr("0x1003713"));

		nextColor();							// go to end of 5th range
		assertEquals(cb.getCurrentAddress(), addr("0x1003723"));

	}

	/**
	 * Tests navigation of offcut ranges when coloring is set from a plugin point-of-view.
	 * @throws Exception 
	 */
	@Test
	public void testPluginNavigateTopBottomOffcutColorRanges() throws Exception {
		loadProgram("notepad");
		configureTopAndBottomRangeTraversal();

		//
		// Set some color ranges
		//
		Color selectionColor = Color.GRAY;
		setColorOverRange(selectionColor, addr("0x10036c0"), addr("0x10036c9"));
		setColorOverRange(selectionColor, addr("0x10036d3"), addr("0x10036d6"));
		setColorOverRange(selectionColor, addr("0x10036e1"), addr("0x10036e6"));
		setColorOverRange(selectionColor, addr("0x10036f7"), addr("0x1003707"));
		setColorOverRange(selectionColor, addr("0x1003713"), addr("0x1003723"));

		//
		// Verify ranges were set as expected
		// 
		goTo(addr("0x1001000")); // an address that starts before all ranges

		// Verify addresses during forward traversal
		nextColor();							// go to beginning of 1st range
		assertEquals(cb.getCurrentAddress(), addr("0x10036c0"));

		nextColor();							// go to end of 1st range  (offcut here)
		assertEquals(cb.getCurrentAddress(), addr("0x10036c6"));

		nextColor();							// go to beginning of 2nd range
		assertEquals(cb.getCurrentAddress(), addr("0x10036d3"));

		nextColor();							// go to end of 2nd range
		assertEquals(cb.getCurrentAddress(), addr("0x10036d5"));

		nextColor();							// go to beginning of 3rd range (offcut here)
		assertEquals(cb.getCurrentAddress(), addr("0x10036e0"));

		nextColor();							// go to end of 3rd range
		assertEquals(cb.getCurrentAddress(), addr("0x10036e6"));

		nextColor();							// go to beginning of 4th range (offcut here)
		assertEquals(cb.getCurrentAddress(), addr("0x10036f5"));

		nextColor();							// go to end of 4th range (offcut here)
		assertEquals(cb.getCurrentAddress(), addr("0x1003703"));

		nextColor();							// go to beginning of 5th range
		assertEquals(cb.getCurrentAddress(), addr("0x1003713"));

		nextColor();							// go to end of 5th range
		assertEquals(cb.getCurrentAddress(), addr("0x1003723"));

	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void setColor(Color color) {
		setColor(color, cb.getCurrentAddress());
	}

	private void setColor(Color color, Address... addresses) {
		for (Address address : addresses) {
			setColor(color, address);
		}
	}

	private void setColorOverRange(Color color, final Address start, final Address end) {
		makeSelection(tool, program, start, end);
		setColor(color, start);
	}

	private void setColor(final Color color, Address address) {
		cb.goTo(new ProgramLocation(program, address));
		ActionContext context = getActionContext();
		performAction(setColorAction, context, false);

		Window chooserWindow = waitForWindow(ColorizingServiceProvider.COLOR_CHOOSER_TITLE);
		assertNotNull("Did not find Color Chooser", chooserWindow);
		GhidraColorChooser colorChooser = findComponent(chooserWindow, GhidraColorChooser.class);
		JButton okButton = findButtonByText(chooserWindow, "OK");
		runSwing(() -> {
			colorChooser.setColor(color);
			okButton.doClick();
		});

		waitForSwing();

		assertColorForAddress(color, address);
	}

	private void setBackgroundFromAPI(Address address, Color color) {
		int id = program.startTransaction("Test - Color Change");

		try {
			colorizingService.setBackgroundColor(address, address, color);

			waitForSwing();
		}
		finally {
			program.endTransaction(id, true);
		}

		program.flushEvents();
		waitForBusyTool(tool);
	}

	private void assertColorForAddress(Color color) {
		Address address = cb.getCurrentAddress();
		assertColorForAddress(color, address);
	}

	private void assertColorForAddress(Color color, Address address) {
		Color appliedColor = colorizingService.getBackgroundColor(address);
		assertEquals(color, appliedColor);

		assertMarkerColorAtAddress(address, color);
	}

	private void assertColorForAddress(Color color, Address... addresses) {
		for (Address address : addresses) {
			assertColorForAddress(color, address);
		}
	}

	private void assertColorForSelection(Color color) {
		ProgramSelection currentSelection = cb.getCurrentSelection();
		assertNotNull(currentSelection);
		assertTrue(!currentSelection.isEmpty());

		AddressSetView appliedColorLocations = colorizingService.getBackgroundColorAddresses(color);
		assertTrue(currentSelection.hasSameAddresses(appliedColorLocations));
	}

	private void clearColor() {
		clearColor(null);
	}

	private void clearColor(Address address) {
		if (address != null) {
			goTo(address);
		}

		ActionContext context = getActionContext();
		performAction(clearColorAction, context, true);
		waitForSwing();
	}

	private void clearAllColors() {
		ActionContext context = getActionContext();
		performAction(clearAllColorsAction, context, true);
		waitForSwing();
	}

	private void assertNoColorForAddress() {
		Address address = cb.getCurrentAddress();
		assertNoColorForAddress(address);
	}

	private void assertNoColorForAddress(Address address) {
		Color appliedColor = colorizingService.getBackgroundColor(address);
		assertEquals(null, appliedColor);

		assertNoMarkerColorAtAddress(address);
	}

	private void assertNoMarkerColorAtAddress(Address address) {
		MarkerService markerService = tool.getService(MarkerService.class);
		MarkerSet markerSet = getColorizingMarkerSet(markerService);
		if (markerSet == null) {
			return; // no markers
		}

		AddressSet addressSet = getAddressSet(markerSet);
		assertTrue(!addressSet.contains(address));
	}

	private void assertMarkerColorAtAddress(Address address, Color color) {
		MarkerService markerService = tool.getService(MarkerService.class);
		MarkerSet markerSet = getColorizingMarkerSet(markerService);
		assertNotNull("No marker set for color at address: " + address, markerSet);

		AddressSet addressSet = getAddressSet(markerSet);
		assertTrue(addressSet.contains(address));
	}

	private AddressSet getAddressSet(final MarkerSet markerSet) {
		final AtomicReference<AddressSet> reference = new AtomicReference<>();
		runSwing(() -> reference.set(markerSet.getAddressSet()));
		return reference.get();
	}

	private MarkerSet getColorizingMarkerSet(final MarkerService markerService) {
		final AtomicReference<MarkerSet> reference = new AtomicReference<>();
		runSwing(
			() -> reference.set(markerService.getMarkerSet(ColorizingPlugin.MARKER_NAME, program)));
		return reference.get();
	}

	private void assertNoColorForSelection(Color clearedColor) {
		ProgramSelection currentSelection = cb.getCurrentSelection();
		assertNotNull(currentSelection);
		assertTrue(!currentSelection.isEmpty());

		AddressSetView appliedColorLocations =
			colorizingService.getBackgroundColorAddresses(clearedColor);
		assertTrue(appliedColorLocations.isEmpty());
	}

	private void assertAllActionsDisabled() {
		assertClearActionsEnabled(false);
		assertSetColorActionEnabled(false);
		assertNavigationActionsEnabled(false);
	}

	private void assertSetColorActionEnabled(boolean enabled) {
		ActionContext context = getActionContext();
		assertTrue((enabled) ? setColorAction.isEnabledForContext(context)
				: !setColorAction.isEnabledForContext(context));
	}

	private void assertClearActionsEnabled(boolean enabled) {
		ActionContext context = getActionContext();
		assertTrue((enabled) ? clearColorAction.isEnabledForContext(context)
				: !clearColorAction.isEnabledForContext(context));
		assertTrue((enabled) ? clearAllColorsAction.isEnabledForContext(context)
				: !clearAllColorsAction.isEnabledForContext(context));
	}

	private void assertNavigationActionsEnabled(boolean enabled) {
		ActionContext context = getActionContext();
		assertTrue((enabled) ? nextColorRangeAction.isEnabledForContext(context)
				: !nextColorRangeAction.isEnabledForContext(context));
		assertTrue((enabled) ? previousColorRangeAction.isEnabledForContext(context)
				: !previousColorRangeAction.isEnabledForContext(context));
	}

	private void assertNextButtonEnabled(boolean enabled) {
		ActionContext context = getActionContext();
		assertTrue((enabled) ? nextColorRangeAction.isEnabledForContext(context)
				: !nextColorRangeAction.isEnabledForContext(context));
	}

	private void assertPreviousButtonEnabled(boolean enabled) {
		ActionContext context = getActionContext();
		assertTrue((enabled) ? previousColorRangeAction.isEnabledForContext(context)
				: !previousColorRangeAction.isEnabledForContext(context));
	}

	private void nextColor() {
		ActionContext context = getActionContext();

		assertTrue("NextColorRangeAction not currently enabled for context",
			nextColorRangeAction.isEnabledForContext(context));

		performAction(nextColorRangeAction, context, true);
	}

	private void previousColor() {
		ActionContext context = getActionContext();

		assertTrue("PreviousColorRangeAction not currently enabled for context",
			previousColorRangeAction.isEnabledForContext(context));

		performAction(previousColorRangeAction, context, true);
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void loadProgram(String programName) throws Exception {
		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
	}

	private void createSelection() {
		FieldPanel fp = cb.getFieldPanel();
		cb.goToField(addr("0x1003698"), "Bytes", 0, 4);
		FieldLocation p1 = fp.getCursorLocation();
		cb.goToField(addr("0x10036a2"), "Address", 0, 1);
		FieldLocation p2 = fp.getCursorLocation();
		FieldSelection selection = new FieldSelection();
		selection.addRange(p1, p2);
		setSelection(fp, selection);
	}

	private void createSelectionBytes(String fromAddress, int fromRow, int fromCol,
			String toAddress, int toRow, int toCol) {
		FieldPanel fp = cb.getFieldPanel();
		cb.goToField(addr(fromAddress), "Bytes", fromRow, fromCol);
		FieldLocation p1 = fp.getCursorLocation();
		cb.goToField(addr(toAddress), "Bytes", toRow, toCol);
		FieldLocation p2 = fp.getCursorLocation();
		FieldSelection selection = new FieldSelection();
		selection.addRange(p1, p2);
		setSelection(fp, selection);
	}

	private void setSelection(FieldPanel fp, FieldSelection sel) {
		fp.setSelection(sel);
		Class<?>[] argClasses = new Class<?>[] { EventTrigger.class };
		Object[] args = new Object[] { EventTrigger.GUI_ACTION };

		runSwing(() -> {
			invokeInstanceMethod("notifySelectionChanged", fp, argClasses, args);
		});
	}

	private ActionContext getActionContext() {
		ActionContext context = cb.getProvider().getActionContext(null);
		if (context == null) {
			context = new ActionContext();
		}
		return context;
	}

	private void configureTopAndBottomRangeTraversal() {
		ToolOptions options = tool.getOptions(GhidraOptions.NAVIGATION_OPTIONS);
		options.setEnum(GhidraOptions.NAVIGATION_RANGE_OPTION,
			RangeNavigationEnum.TopAndBottomOfRange);
	}

	private void goTo(Address address) {
		cb.goTo(new ProgramLocation(program, address));
	}
}
