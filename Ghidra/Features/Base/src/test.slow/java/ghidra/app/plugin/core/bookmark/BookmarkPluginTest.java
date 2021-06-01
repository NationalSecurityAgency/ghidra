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
package ghidra.app.plugin.core.bookmark;

import static org.junit.Assert.*;

import java.awt.Rectangle;
import java.awt.event.*;
import java.util.*;

import javax.swing.JComboBox;
import javax.swing.JTextField;
import javax.swing.text.JTextComponent;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.filter.FilterOptions;
import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import generic.test.AbstractGenericTest;
import ghidra.app.cmd.data.CreateStructureCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.*;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;
import ghidra.util.Msg;
import ghidra.util.table.field.AddressBasedLocation;

public class BookmarkPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private BookmarkPlugin plugin;
	private BookmarkProvider provider;
	private CodeBrowserPlugin cbPlugin;
	private CodeViewerProvider codeViewerProvider;
	private Bookmark[] bookmarks;
	private GTable table;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.showTool();
		tool.addPlugin(BookmarkPlugin.class.getName());
		setUpCodeBrowserTool(tool);
		plugin = env.getPlugin(BookmarkPlugin.class);
		provider = (BookmarkProvider) getInstanceField("provider", plugin);
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		codeViewerProvider = cbPlugin.getProvider();
		tool.setSize(2000, 800);
		program = buildProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		initProgram();
	}

	private Program buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true, ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0xb000);
		builder.addBytesFallthrough("0x1001010");
		builder.addBytesFallthrough("0x1001020");
		builder.addBytesFallthrough("0x1001030");
		builder.addBytesFallthrough("0x1001040");
		builder.disassemble("0x1001010", 1);
		builder.disassemble("0x1001020", 1);
		builder.disassemble("0x1001030", 1);
		builder.disassemble("0x1001040", 1);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testFiltering() throws Exception {
		showBookmarkProvider();
		BookmarkManager bmMgr = program.getBookmarkManager();
		BookmarkType[] types = bmMgr.getBookmarkTypes();
		assertEquals(8, types.length);

		checkBookmarkTable(bookmarks);
		DockingActionIf pa = getAction(plugin, "Filter Bookmarks");
		performAction(pa, false);

		FilterDialog fd = waitForDialogComponent(FilterDialog.class);
		runSwing(() -> {
			fd.setFilter("Type1", false);
			fd.setFilter("Type2", false);
			fd.okCallback();
		});

		Bookmark[] bms = new Bookmark[] { bookmarks[6], bookmarks[7], bookmarks[8] };
		checkBookmarkTable(bms);
	}

	@Test
	public void testFilteringByText() throws Exception {

		showBookmarkProvider();

		checkBookmarkTable(bookmarks);
		BookmarkTableModel model = (BookmarkTableModel) table.getModel();
		DefaultTableTextFilterFactory<BookmarkRowObject> factory =
			new DefaultTableTextFilterFactory<>(new FilterOptions());
		DefaultRowFilterTransformer<BookmarkRowObject> transformer =
			new DefaultRowFilterTransformer<>(model, table.getColumnModel());

		runSwing(() -> model.setTableFilter(factory.getTableFilter("help", transformer)));

		Bookmark[] bms = new Bookmark[] {};
		checkBookmarkTable(bms);

		runSwing(() -> model.setTableFilter(factory.getTableFilter("Test20", transformer)));

		bms = new Bookmark[] { bookmarks[1], bookmarks[2] };
		checkBookmarkTable(bms);

		runSwing(() -> model.setTableFilter(null));

		checkBookmarkTable(bookmarks);
	}

	@Test
	public void testFilterPersistence() throws Exception {

		// we want to use a different tool than the rest of the test
		reloadTool();

		showBookmarkProvider();

		// disable some types via the filter dialog
		BookmarkManager bmMgr = program.getBookmarkManager();
		BookmarkType[] types = bmMgr.getBookmarkTypes();

		// use a type that will be there when we relaunch the program
		String testTypeName = "Note";
		DockingActionIf pa = getAction(plugin, "Filter Bookmarks");
		performAction(pa, false);

		FilterDialog fd = waitForDialogComponent(FilterDialog.class);
		runSwing(() -> {
			// turn off all types 
			for (BookmarkType type : types) {
				fd.setFilter(type.getTypeString(), false);
			}

			// turn on our test type
			fd.setFilter(testTypeName, true);

			// close the filter dialog
			fd.okCallback();
		});

		waitForTable();

		// sanity check
		for (BookmarkType type : types) {
			boolean isTestType = type.getTypeString().equals(testTypeName);
			boolean isEnabled = provider.isShowingType(type.getTypeString());
			assertEquals("Filter is not toggled as expected - '" + testTypeName + "'", isTestType,
				isEnabled);
		}

		// save the tool and program
		tool = saveTool(env.getProject(), tool);

		// close and re-open the tool
		reloadTool();

		// load
		showBookmarkProvider();

		// make sure the filters match the saved setting        
		BookmarkType[] reloadedTypes = bmMgr.getBookmarkTypes();
		for (BookmarkType type : reloadedTypes) {
			boolean isTestType = type.getTypeString().equals(testTypeName);
			boolean isEnabled = provider.isShowingType(type.getTypeString());
			assertEquals("Filter is not toggled as expected - '" + testTypeName + "'", isTestType,
				isEnabled);
		}
	}

	@Test
	public void testFilterPersistenceWithMissingType() throws Exception {
		// load
		// we want to use a different tool than the rest of the test
		reloadTool();

		showBookmarkProvider();

		// disable some types via the filter dialog
		BookmarkManager bmMgr = program.getBookmarkManager();
		BookmarkType[] types = bmMgr.getBookmarkTypes();

		// use a type that will NOT be there when we relaunch the program
		String testTypeName = "TypeNew";
		createBookmarkForType(testTypeName);
		DockingActionIf pa = getAction(plugin, "Filter Bookmarks");
		performAction(pa, false);

		final FilterDialog fd = waitForDialogComponent(FilterDialog.class);
		runSwing(() -> {
			// turn off all types 
			for (BookmarkType type : types) {
				fd.setFilter(type.getTypeString(), false);
			}

			// turn on our test type
			fd.setFilter(testTypeName, true);
			fd.okCallback();
		});
		waitForSwing();

		// sanity check
		for (BookmarkType type : types) {
			boolean isTestType = type.getTypeString().equals(testTypeName);
			boolean isEnabled = provider.isShowingType(type.getTypeString());
			assertEquals("Filter is not toggled as expected - '" + testTypeName + "'", isTestType,
				isEnabled);
		}

		// save the tool and program
		tool = saveTool(env.getProject(), tool);

		// close and re-open the tool
		reloadTool();

		// load
		showBookmarkProvider();

		/*
		 	Verify that *all* bookmark types are enabled.  Since the program does not contain
		 	the new type added above before the restart, the bookmark table model will drop
		 	that type upon reload.
		 */
		bmMgr = program.getBookmarkManager();
		BookmarkType[] reloadedTypes = bmMgr.getBookmarkTypes();
		for (BookmarkType type : reloadedTypes) {
			boolean isEnabled = provider.isShowingType(type.getTypeString());
			assertTrue("Filter is not enabled as expected - '" + testTypeName + "'", isEnabled);
		}
	}

	@Test
	public void testSelectionGoto() throws Exception {

		showBookmarkProvider();

		// Location changes if single bookmark selected
		doubleClickRow(1);
		assertEquals(addrFactory.getAddress("01001020"), cbPlugin.getCurrentAddress());

		// Location does not change
		doubleClickRow(2);
		assertEquals(addrFactory.getAddress("01001020"), cbPlugin.getCurrentAddress());

		doubleClickRow(5);
		assertEquals(addrFactory.getAddress("01001040"), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testSelectionMakeSelection() throws Exception {

		showBookmarkProvider();

		selectRow(2, false);
		selectRow(5, true);

		DockingActionIf action = getAction(plugin, "Select Bookmark Locations");
		action.actionPerformed(new ActionContext());

		AddressSet set = new AddressSet();

		set.addRange(addr("0x01001020"), addr("0x01001021"));
		set.addRange(addr("0x01001040"), addr("0x01001041"));
		ProgramSelection sel = cbPlugin.getCurrentSelection();
		assertEquals(set, sel);

		selectRow(0, false);
		selectRow(3, true);
		action.actionPerformed(new ActionContext());
		sel = cbPlugin.getCurrentSelection();
		set.clear();
		set.addRange(addr("0x01001010"), addr("0x01001011"));
		set.addRange(addr("0x01001030"), addr("0x01001031"));
		assertEquals(set, sel);

	}

	@Test
	public void testSelectionDelete() throws Exception {

		showBookmarkProvider();

		selectRow(2, false);

		DockingActionIf deleteAction = getAction(plugin, "Delete Bookmarks");
		performAction(deleteAction, true);

		Bookmark[] bms = new Bookmark[] { bookmarks[0], bookmarks[1], bookmarks[3], bookmarks[4],
			bookmarks[5], bookmarks[6], bookmarks[7], bookmarks[8] };
		checkBookmarkTable(bms);

		selectRow(2, false);
		selectRow(5, true);

		performAction(deleteAction, true);
		bms = new Bookmark[] { bookmarks[0], bookmarks[1], bookmarks[4], bookmarks[5], bookmarks[7],
			bookmarks[8] };
		checkBookmarkTable(bms);

	}

	@Test
	public void testEditCategory() throws Exception {
		showBookmarkProvider();

		assertEquals("Cat1b", table.getValueAt(2, 1));

		waitForTable();

		clickTableCell(table, 2, 1, 2);

		JComboBox<?> combo = (JComboBox<?>) table.getEditorComponent();
		JTextComponent comp = (JTextComponent) (combo.getEditor().getEditorComponent());

		assertEquals(2, combo.getItemCount());

		runSwing(() -> comp.selectAll());
		triggerText(comp, "foo\n");

		assertEquals("foo", table.getValueAt(2, 1));

	}

	@Test
	public void testEditComment() throws Exception {

		showBookmarkProvider();

		assertEquals("Cmt1C", table.getValueAt(2, 2));

		clickTableCell(table, 2, 2, 2);

		JTextField field = (JTextField) table.getEditorComponent();

		setText(field, "foo");
		triggerEnter(field);

		int rowCount = table.getRowCount();
		boolean hasFoo = false;
		for (int i = 0; i < rowCount; i++) {
			Object value = table.getValueAt(i, 2);
			if ("foo".equals(value.toString())) {
				hasFoo = true;
				break;
			}
		}
		assertTrue(hasFoo);
	}

	@Test
	public void testAddBookmark() throws Exception {
		showBookmarkProvider();
		checkBookmarkTable(bookmarks);

		DockingActionIf pa = getAction(plugin, "Add Bookmark");
		performAction(pa, codeViewerProvider, false);

		CreateBookmarkDialog d = waitForDialogComponent(CreateBookmarkDialog.class);
		assertNotNull("Could not find the Create Bookmark dialog", d);
		runSwing(() -> {
			JTextField commentTextField =
				(JTextField) AbstractGenericTest.getInstanceField("commentTextField", d);
			commentTextField.setText("My Comment");
			JComboBox<?> categoryComboBox =
				(JComboBox<?>) AbstractGenericTest.getInstanceField("categoryComboBox", d);
			categoryComboBox.setSelectedItem("fred");
			d.okCallback();
		});

		List<Bookmark> list = getBookmarks(program.getBookmarkManager());
		assertEquals(10, list.size());
		Bookmark[] bks = new Bookmark[10];
		list.toArray(bks);
		Arrays.sort(bks);
		checkBookmarkTable(bks);

		undo(program);
		checkBookmarkTable(bookmarks);

		redo(program);
		checkBookmarkTable(bks);
	}

	@Test
	public void testDeleteBookmarkAction() throws Exception {
		List<Bookmark> list = getBookmarks(program.getBookmarkManager());
		Bookmark bookmark = list.get(0);
		Address address = bookmark.getAddress();
		DeleteBookmarkAction action = new DeleteBookmarkAction(plugin, bookmark, true);
		MarkerLocation markerLocation = new MarkerLocation(null, program, address, 0, 0);
		performAction(action, createContext(markerLocation), true);
		list = getBookmarks(program.getBookmarkManager());
		assertFalse(list.contains(bookmark));

		bookmark = list.get(0);
		address = bookmark.getAddress();
		action = new DeleteBookmarkAction(plugin, bookmark, false);
		markerLocation = new MarkerLocation(null, program, address, 0, 0);
		performAction(action, createContext(markerLocation), true);
		list = getBookmarks(program.getBookmarkManager());
		assertFalse(list.contains(bookmark));
	}

	@Test
	public void testDeleteBookmarkUpdatesTable() throws Exception {

		//
		// This test catches a bug with removing a deleted bookmark from the table.   The bug was
		// triggered by a failure in the binary search.  Specifically, if the binary search does
		// not touch the item to be deleted, then the item would not get removed from the table.
		// 

		showBookmarkProvider();

		List<Bookmark> list = getBookmarks(program.getBookmarkManager());
		int n = list.size();
		int rowCount = n;
		for (int i = 0; i < n; i++) {

			// cannot merely delete from the beginning to trigger this bug
			int index = getRandomInt(0, list.size() - 1);
			Bookmark bookmark = list.get(index);
			Address address = bookmark.getAddress();
			DeleteBookmarkAction action = new DeleteBookmarkAction(plugin, bookmark, true);
			MarkerLocation markerLocation = new MarkerLocation(null, program, address, 0, 0);
			performAction(action, createContext(markerLocation), true);

			waitForTable();
			assertEquals(rowCount - 1, table.getRowCount());
			list = getBookmarks(program.getBookmarkManager());
			rowCount = list.size();
		}
	}

	@Test
	public void testMultipleDelete() throws Exception {
		showBookmarkProvider();

		// note: we want to test a specific code path, so we must delete more than 20 items

		// add more to our current set
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		addCmd.add(new BookmarkEditCmd(addr("01001110"), "Type1", "Cat1a", "Cmt1A"));
		addCmd.add(new BookmarkEditCmd(addr("01001120"), "Type1", "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01001120"), "Type1", "Cat1b", "Cmt1C"));
		addCmd.add(new BookmarkEditCmd(addr("01001130"), "Type1", "Cat1b", "Cmt1D"));
		addCmd.add(new BookmarkEditCmd(addr("01001130"), "Type2", "Cat2a", "Cmt2E"));
		addCmd.add(new BookmarkEditCmd(addr("01001140"), "Type2", "Cat2b", "Cmt2F"));
		addCmd.add(new BookmarkEditCmd(addr("01001140"), "Type3", "Cat3a", "Cmt2G"));
		addCmd.add(new BookmarkEditCmd(addr("01001150"), "Type3", "Cat3a", "Cmt2H"));
		addCmd.add(new BookmarkEditCmd(addr("01001160"), "Type3", "Cat3b", "Cmt2I"));
		addCmd.add(new BookmarkEditCmd(addr("01001210"), "Type1", "Cat1a", "Cmt1A"));
		addCmd.add(new BookmarkEditCmd(addr("01001220"), "Type1", "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01001220"), "Type1", "Cat1b", "Cmt1C"));
		addCmd.add(new BookmarkEditCmd(addr("01001230"), "Type1", "Cat1b", "Cmt1D"));
		addCmd.add(new BookmarkEditCmd(addr("01001230"), "Type2", "Cat2a", "Cmt2E"));
		addCmd.add(new BookmarkEditCmd(addr("01001240"), "Type2", "Cat2b", "Cmt2F"));
		addCmd.add(new BookmarkEditCmd(addr("01001240"), "Type3", "Cat3a", "Cmt2G"));
		addCmd.add(new BookmarkEditCmd(addr("01001250"), "Type3", "Cat3a", "Cmt2H"));
		addCmd.add(new BookmarkEditCmd(addr("01001260"), "Type3", "Cat3b", "Cmt2I"));
		applyCmd(program, addCmd);

		waitForTable();

		selectAllTableRows();
		runSwing(() -> provider.delete());
		waitForCondition(() -> table.getRowCount() == 0, "Bookmarks not deleted");
	}

	@Test
	public void testSetNoteOverDiscontiguosSelection() throws Exception {

		Address address1 = addr("01001160");
		Address address2 = addr("01001260");

		final AddressSet addressSet = new AddressSet();
		addressSet.add(address1);
		addressSet.add(address2);

		runSwing(() -> tool.firePluginEvent(
			new ProgramSelectionPluginEvent("Test", new ProgramSelection(addressSet), program)));

		runSwing(() -> plugin.setNote(null, "Cat1", "My Note"));

		List<Address> addresses = new ArrayList<>();
		List<Bookmark> list = getBookmarks(program.getBookmarkManager());
		for (Bookmark bookmark : list) {
			addresses.add(bookmark.getAddress());
		}

		assertTrue(addresses.contains(address1));
		assertTrue(addresses.contains(address2));
	}

	@Test
	public void testMarkerAdded() throws Exception {
		MarkerService markerService = tool.getService(MarkerService.class);
		MarkerSet markerSet = markerService.getMarkerSet("Type1 Bookmarks", program);
		AddressSet addressSet = runSwing(() -> markerSet.getAddressSet());
		assertFalse(addressSet.contains(addr("01001100")));
		assertFalse(addressSet.contains(addr("01001120")));

		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		addCmd.add(new BookmarkEditCmd(addr("01001100"), "Type1", "Cat1a", "Cmt1A"));
		addCmd.add(new BookmarkEditCmd(addr("01001120"), "Type1", "Cat1a", "Cmt1B"));
		applyCmd(program, addCmd);

		MarkerSet type1MarkerSet = markerService.getMarkerSet("Type1 Bookmarks", program);
		addressSet = runSwing(() -> type1MarkerSet.getAddressSet());
		assertTrue(addressSet.contains(addr("01001100")));
		assertTrue(addressSet.contains(addr("01001120")));
	}

	@Test
	public void testDeleteOffcutBookmarks() throws Exception {
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		Address a = addr("0100b6db");
		for (int i = 0; i < 20; i++) {
			addCmd.add(new BookmarkEditCmd(a, "Type1", "Cat1a", "Cmt1A"));
			a = a.add(1);
		}
		applyCmd(program, addCmd);

		//make a structure
		CreateStructureCmd cmd = new CreateStructureCmd(addr("0100b6db"), 20);
		applyCmd(program, cmd);

		List<DockingActionIf> actions = runSwing(() -> plugin.getPopupActions(null,
			createContext(new MarkerLocation(null, program, addr("0100b6db"), 0, 0))));
		assertEquals(10, actions.size());
	}

	@Test
	public void testIteratorFromAddress() {
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		Iterator<Bookmark> iterator = bookmarkManager.getBookmarksIterator(addr("1001000"), true);

		Bookmark bookmark = iterator.next();
		assertEquals(addr("1001010"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001020"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001020"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001030"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001030"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001040"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001040"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001050"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001060"), bookmark.getAddress());

		bookmarkManager = program.getBookmarkManager();
		iterator = bookmarkManager.getBookmarksIterator(addr("1001040"), true);

		bookmark = iterator.next();
		assertEquals(addr("1001040"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001040"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001050"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001060"), bookmark.getAddress());
	}

	@Test
	public void testIteratorFromAddress_Backwards() {
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		Iterator<Bookmark> iterator = bookmarkManager.getBookmarksIterator(addr("10010060"), false);

		Bookmark bookmark = iterator.next();
		assertEquals(addr("1001060"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001050"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001040"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001040"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001030"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001030"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001020"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001020"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001010"), bookmark.getAddress());

		bookmarkManager = program.getBookmarkManager();
		iterator = bookmarkManager.getBookmarksIterator(addr("1001030"), false);

		bookmark = iterator.next();
		assertEquals(addr("1001030"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001030"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001020"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001020"), bookmark.getAddress());
		bookmark = iterator.next();
		assertEquals(addr("1001010"), bookmark.getAddress());
	}

	@Test
	public void testRemoveBookmarksByType() {

		List<Bookmark> list = getBookmarks(program.getBookmarkManager());
		assertFalse(list.isEmpty());

		BookmarkManager bm = program.getBookmarkManager();
		tx(program, () -> {
			bm.removeBookmarks(BookmarkType.ALL_TYPES);
		});

		list = getBookmarks(program.getBookmarkManager());
		assertTrue(list.isEmpty());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void createBookmarkForType(String testTypeName) {

		BookmarkEditCmd cmd =
			new BookmarkEditCmd(addr("01001020"), testTypeName, "Category", "My comment");
		assertTrue(applyCmd(program, cmd));
	}

	private void loadDefaultTool() throws Exception {
		program = buildProgram();

		// UNUSUAL CODE ALERT!: 
		// Instead of calling env.launchDefaultTool(), we call this version, passing in the 
		// default tool's name.  The former method now *always load the tool from Ghidra's 
		// resources and not from the user's area*.  This is a test feature.  We use this other
		// call here because sometimes this method (loadDefaultTool()) is called to reload the
		// tool after the test saved some changes.  Calling the other method will not get the 
		// changes, but this one will.
		tool = env.launchTool("TestCodeBrowser", program.getDomainFile());

		plugin = getPlugin(tool, BookmarkPlugin.class);
		provider = (BookmarkProvider) getInstanceField("provider", plugin);
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);

		initProgram();
	}

	private void initProgram() {
		addrFactory = program.getAddressFactory();

		// Remove all existing bookmarks
		BookmarkDeleteCmd delCmd = new BookmarkDeleteCmd(addrFactory.getAddressSet(), null, null);
		applyCmd(program, delCmd);

		// Add specific bookmarks
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		addCmd.add(new BookmarkEditCmd(addr("01001010"), "Type1", "Cat1a", "Cmt1A"));
		addCmd.add(new BookmarkEditCmd(addr("01001020"), "Type1", "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01001020"), "Type1", "Cat1b", "Cmt1C"));
		addCmd.add(new BookmarkEditCmd(addr("01001030"), "Type1", "Cat1b", "Cmt1D"));
		addCmd.add(new BookmarkEditCmd(addr("01001030"), "Type2", "Cat2a", "Cmt2E"));
		addCmd.add(new BookmarkEditCmd(addr("01001040"), "Type2", "Cat2b", "Cmt2F"));
		addCmd.add(new BookmarkEditCmd(addr("01001040"), "Type3", "Cat3a", "Cmt2G"));
		addCmd.add(new BookmarkEditCmd(addr("01001050"), "Type3", "Cat3a", "Cmt2H"));
		addCmd.add(new BookmarkEditCmd(addr("01001060"), "Type3", "Cat3b", "Cmt2I"));
		applyCmd(program, addCmd);

		AddLabelCmd labelCmd =
			new AddLabelCmd(addr("01001020"), "Test20", false, SourceType.USER_DEFINED);
		applyCmd(program, labelCmd);

		labelCmd = new AddLabelCmd(addr("01001050"), "Test50", false, SourceType.USER_DEFINED);
		applyCmd(program, labelCmd);

		List<Bookmark> list = getBookmarks(program.getBookmarkManager());
		assertEquals(9, list.size());
		bookmarks = new Bookmark[9];
		list.toArray(bookmarks);
		Arrays.sort(bookmarks);
	}

	private List<Bookmark> getBookmarks(BookmarkManager mgr) {
		List<Bookmark> list = new ArrayList<>();
		Iterator<Bookmark> it = mgr.getBookmarksIterator();
		while (it.hasNext()) {
			list.add(it.next());
		}
		return list;
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void setUpCodeBrowserTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
	}

	private void reloadTool() throws Exception {

		env.closeTool(tool);
		loadDefaultTool();
	}

	private void selectAllTableRows() {
		runSwing(() -> table.selectAll());
	}

	private void showBookmarkProvider() throws Exception {
		DockingActionIf action = getAction(plugin, "Bookmarks");
		performAction(action, true);
		table = plugin.getBookmarkTable();
		waitForTable();
	}

	@SuppressWarnings("unchecked")
	private void waitForTable() {
		waitForTableModel((ThreadedTableModel<Bookmark, ?>) table.getModel());
	}

	private void checkBookmarkTable(Bookmark[] bookmarksToCheck) {
		waitForBusyTool(tool);
		waitForTable();

		int tableRowCount = table.getRowCount();

		if (bookmarksToCheck.length != tableRowCount) {
			Msg.debug(this, "Expected: ");
			for (Bookmark bookmark : bookmarksToCheck) {
				Msg.debug(this, "\t" + bookmark);
			}

			Msg.debug(this, "Found: ");
			BookmarkManager bookmarkManager = program.getBookmarkManager();
			@SuppressWarnings("unchecked")
			List<?> modelData = ((ThreadedTableModel<Bookmark, ?>) table.getModel()).getModelData();
			for (Object row : modelData) {
				Bookmark bookmark = bookmarkManager.getBookmark(((BookmarkRowObject) row).getKey());
				Msg.debug(this, "\t" + bookmark);
			}

			Assert.fail();
		}

		int n = table.getRowCount();

		for (Bookmark element : bookmarksToCheck) {
			boolean foundMatch = false;
			for (int j = 0; j < n; j++) {
				if (checkTable(element, j)) {
					foundMatch = true;
					break;
				}
			}
			if (!foundMatch) {
				Assert.fail("Could not find bookmark: " + element);
			}
		}
	}

	private boolean checkTable(Bookmark bm, int row) {
		if (!bm.getTypeString().equals(table.getValueAt(row, 0))) {
			return false;
		}
		if (!bm.getCategory().equals(table.getValueAt(row, 1))) {
			return false;
		}
		if (!bm.getComment().equals(table.getValueAt(row, 2))) {
			return false;
		}
		AddressBasedLocation location = (AddressBasedLocation) table.getValueAt(row, 3);
		if (!bm.getAddress().equals(location.getAddress())) {
			return false;
		}

		Symbol[] syms = program.getSymbolTable().getSymbols(bm.getAddress());
		if (syms.length != 0) {
			if (!syms[0].getName().equals(table.getValueAt(row, 4))) {
				return false;
			}
		}
		else {
			return table.getValueAt(row, 4) == null;
		}
		return true;
	}

	private void selectRow(final int row, final boolean addToSelection) {
		runSwing(() -> {

			SelectionManager selectionManager = table.getSelectionManager();
			if (addToSelection) {
				selectionManager.addSelectionInterval(row, row);
			}
			else {
				selectionManager.setSelectionInterval(row, row);
			}
		});
	}

	private void doubleClickRow(final int row) {
		Runnable r = () -> {

			Rectangle rectangle = table.getCellRect(row, 0, false);
			MouseListener[] listeners = table.getMouseListeners();

			long time = System.currentTimeMillis();
			int mask = InputEvent.BUTTON1_DOWN_MASK;
			int clickCount = 2;
			MouseEvent evt = new MouseEvent(table, MouseEvent.MOUSE_PRESSED, time, mask,
				rectangle.x, rectangle.y, clickCount, false, MouseEvent.BUTTON1);
			for (MouseListener element1 : listeners) {
				element1.mousePressed(evt);
			}

			evt = new MouseEvent(table, MouseEvent.MOUSE_RELEASED, time, mask, rectangle.x,
				rectangle.y, clickCount, false, MouseEvent.BUTTON1);
			for (MouseListener element2 : listeners) {
				element2.mouseReleased(evt);
			}

			evt = new MouseEvent(table, MouseEvent.MOUSE_CLICKED, time, mask, rectangle.x,
				rectangle.y, clickCount, false, MouseEvent.BUTTON1);
			for (MouseListener element3 : listeners) {
				element3.mouseClicked(evt);
			}
		};
		runSwing(r);
	}

}
