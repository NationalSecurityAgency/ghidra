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

import javax.swing.Icon;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.bookmark.BookmarkEditCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

public class NextPrevCodeUnitPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private ProgramBuilder builder;
	private Program program;
	private CodeBrowserPlugin cb;
	private BookmarkManager bookmarkManager;

	private DockingActionIf direction;
	private DockingActionIf invert;
	private DockingActionIf nextInstruction;
	private DockingActionIf nextData;
	private DockingActionIf nextUndefined;
	private DockingActionIf nextLabel;
	private DockingActionIf nextFunction;
	private DockingActionIf nextByteValue;
	private MultiStateDockingAction<String> nextBookmark;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@SuppressWarnings("unchecked") // we know that bookmarks is of type String
	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		loadProgram();
		tool = env.launchDefaultTool(program);

		NextPrevCodeUnitPlugin p = getPlugin(tool, NextPrevCodeUnitPlugin.class);
		direction = getAction(p, "Toggle Search Direction");
		invert = getAction(p, "Invert Search Logic");
		nextInstruction = getAction(p, "Next Instruction");
		nextData = getAction(p, "Next Data");
		nextUndefined = getAction(p, "Next Undefined");
		nextLabel = getAction(p, "Next Label");
		nextFunction = getAction(p, "Next Function");
		nextByteValue = getAction(p, "Next Matching Byte Values");

		nextBookmark = (MultiStateDockingAction<String>) getAction(p, "Next Bookmark");

		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void loadProgram() throws Exception {

		// create a grouping of data types to test the Byte Value searching

		builder = new ClassicSampleX86ProgramBuilder();

		program = builder.getProgram();
		addrFactory = program.getAddressFactory();
		bookmarkManager = program.getBookmarkManager();
	}

	private void addData() throws Exception {
		addType("01001010", "52 65 67 69", new DWordDataType());
		addType("01001016", "64 00 6f 00 77", new DWordDataType());
		addType("0100101c", "43 68 6f 6f", new DWordDataType());
		addType("01001020", "43 68 6f 6f", new DWordDataType());
		addType("01001024", "43 68 6f 6f", new DWordDataType());
		addType("0100102a", "15 00", new DWordDataType());
	}

	private void addType(String addrString, String bytes, DataType dt)
			throws Exception {
		builder.setBytes(addrString, bytes);
		builder.applyDataType(addrString, dt);
	}

	@Test
	public void testToggle() throws Exception {

		Icon upIcon = new GIcon("icon.up");
		Icon downIcon = new GIcon("icon.down");

		assertEquals(downIcon, direction.getToolBarData().getIcon());
		assertStartsWith("Go To Next Instruction", nextInstruction.getDescription());
		assertStartsWith("Go To Next Data", nextData.getDescription());
		assertStartsWith("Go To Next Undefined", nextUndefined.getDescription());
		assertStartsWith("Go To Next Label", nextLabel.getDescription());
		assertStartsWith("Go To Next Function", nextFunction.getDescription());
		assertStartsWith("Go To Next Bookmark: All Types", nextBookmark.getDescription());

		toggleDirection();

		assertEquals(upIcon, direction.getToolBarData().getIcon());
		assertStartsWith("Go To Previous Instruction", nextInstruction.getDescription());
		assertStartsWith("Go To Previous Data", nextData.getDescription());
		assertStartsWith("Go To Previous Undefined", nextUndefined.getDescription());
		assertStartsWith("Go To Previous Label", nextLabel.getDescription());
		assertStartsWith("Go To Previous Function", nextFunction.getDescription());
		assertStartsWith("Go To Previous Bookmark: All Types", nextBookmark.getDescription());

		toggleDirection();

		assertEquals(downIcon, direction.getToolBarData().getIcon());
		assertStartsWith("Go To Next Instruction", nextInstruction.getDescription());
		assertStartsWith("Go To Next Data", nextData.getDescription());
		assertStartsWith("Go To Next Undefined", nextUndefined.getDescription());
		assertStartsWith("Go To Next Label", nextLabel.getDescription());
		assertStartsWith("Go To Next Function", nextFunction.getDescription());
		assertStartsWith("Go To Next Bookmark: All Types", nextBookmark.getDescription());
	}

	@Test
	public void testSearchInstruction() throws Exception {

		assertAddress("0x1001000");
		nextInstruction();
		assertAddress("0x1002239");
		nextInstruction();
		assertAddress("0x1002cf5");

		toggleDirection();

		nextInstruction();
		assertAddress("0x100294d");
		nextInstruction();

		// no more instructions, this is the last range
		assertAddress("0x100294d");
	}

	@Test
	public void testSearchNotInstruction() throws Exception {

		negateSearch();

		assertAddress("0x1001000");
		nextInstruction();
		assertAddress("0x01002950");
		nextInstruction();
		assertAddress("0x01002d6e");

		toggleDirection();

		nextInstruction();
		assertAddress("0x01002cf4");
		nextInstruction();
		assertAddress("0x01002238");
	}

	@Test
	public void testSearchData() throws Exception {

		assertAddress("0x1001000");
		nextData();
		assertAddress("0x1001058");
		nextData();
		assertAddress("0x1001080");

		toggleDirection();

		nextData();
		assertAddress("0x1001058");
		nextData();
		assertAddress("0x01001008");
	}

	@Test
	public void testSearchNotData() throws Exception {

		negateSearch();

		assertAddress("0x1001000");
		nextData();
		assertAddress("0x0100100c");
		nextData();
		assertAddress("0x0100105c");

		toggleDirection();

		nextData();
		assertAddress("0x01001057");
		nextData();
		// no more undefined data or instructions, this is the last range
		assertAddress("0x1001057");
	}

	@Test
	public void testSearchUndefined() throws Exception {

		assertAddress("0x1001000");
		nextUndefined();
		assertAddress("0x100100c");
		nextUndefined();
		assertAddress("0x100105c");

		toggleDirection();

		nextUndefined();
		assertAddress("0x1001057");
		nextUndefined();
		// no more undefined data, this is the last range
		assertAddress("0x1001057");
	}

	@Test
	public void testSearchNotUndefined() throws Exception {

		negateSearch();

		assertAddress("0x1001000");
		nextUndefined();
		assertAddress("0x1001058");
		nextUndefined();
		assertAddress("0x1001080");

		toggleDirection();

		nextUndefined();
		assertAddress("0x1001058");
		nextUndefined();
		assertAddress("0x1001008");
	}

	@Test
	public void testSearchLabel() throws Exception {

		assertAddress("0x1001000");
		nextLabel();
		assertAddress("0x1001004");
		nextLabel();
		assertAddress("0x1001008");

		toggleDirection();

		nextLabel();
		assertAddress("0x1001004");
		nextLabel();
		assertAddress("0x1001000");
		nextLabel();

		// no more labels, this is the last range
		assertAddress("0x1001000");
	}

	@Test
	public void testSearchNotLabel() throws Exception {

		negateSearch();

		assertAddress("0x1001000");
		nextLabel();
		assertAddress("0x100100c");
		nextLabel();
		assertAddress("0x100105c");

		toggleDirection();

		nextLabel();
		assertAddress("0x1001057");
		nextLabel();
		assertAddress("0x1001057"); // no more non-labels
	}

	@Test
	public void testSearchFunction() throws Exception {

		assertAddress("0x1001000");
		performAction(nextFunction, cb.getProvider(), true);
		assertAddress("0x100194b");
		performAction(nextFunction, cb.getProvider(), true);
		assertAddress("0x1001ae3");

		toggleDirection();
		performAction(nextFunction, cb.getProvider(), true);
		assertAddress("0x100194b");
		performAction(nextFunction, cb.getProvider(), true);

		// no more functions, this is the last range
		assertAddress("0x100194b");
	}

	@Test
	public void testSearchNotFunction() throws Exception {

		Address a1 = addInstructions("0x01006600");
		Address a2 = addInstructions("0x0100662a");

		assertAddress("0x1001000");

		// search wit the function action in the inverted mode
		negateSearch();

		performAction(nextFunction, cb.getProvider(), true);
		assertAddress(a1);
		performAction(nextFunction, cb.getProvider(), true);
		assertAddress(a2);

		toggleDirection();

		performAction(nextFunction, cb.getProvider(), true);
		assertAddress("0x1006603");
		performAction(nextFunction, cb.getProvider(), true);

		// no more functions, this is the last range
		assertAddress("0x1006603");
	}

	@Test
	public void testSearchNotBytesValue_SingleByte() throws Exception {

		/*
		 	01005ad5 50              ??         50h    P
		    01005ad6 56              ??         56h    V
		    01005ad7 56              ??         56h    V
		    01005ad8 56              ??         56h    V
		    01005ad9 53              ??         53h    S
		 */

		negateSearch();

		goTo(tool, program, addr("01005ad5"));

		nextByteValue();
		assertAddress("01005ad6");
		nextByteValue();
		assertAddress("01005ad9");

		toggleDirection();

		nextByteValue();
		assertAddress("01005ad8");
		nextByteValue();
		assertAddress("01005ad5");
	}

	@Test
	public void testSearchNotBytesValue_Instruction() throws Exception {

		/*
		 	01005a49 8b 3d 14        MOV        EDI,dword ptr [DAT_01001214]
		         12 00 01
		    01005a4f 56              PUSH       ESI
		    01005a50 56              PUSH       ESI
		    01005a51 6a 0e           PUSH       0xe
		    01005a53 ff 35 d4        PUSH       dword ptr [DAT_010087d4]
		             87 00 01
		    01005a59 ff d7           CALL       EDI
		 */

		negateSearch();

		goTo(tool, program, addr("01005a49"));

		nextByteValue();
		assertAddress("01005a4f");
		nextByteValue();
		assertAddress("01005a51");

		toggleDirection();

		nextByteValue();
		assertAddress("01005a50");
		nextByteValue();
		assertAddress("01005a49");
	}

	@Test
	public void testSearchBytesValue_Data() throws Exception {

		/*
		 
		 	01001010 52 65 67 69     ddw        69676552h
		    01001014 00              ??         00h
		    01001015 00              ??         00h
		    01001016 64 00 6f 00     ddw        6F0064h
		    0100101a 77              ??         77h    w
		    0100101b 00              ??         00h
		    0100101c 43 68 6f 6f     ddw        6F6F6843h
		    01001020 43 68 6f 6f     ddw        6F6F6843h
		    01001024 43 68 6f 6f     ddw        6F6F6843h
		    01001028 00              ??         00h
		    01001029 00              ??         00h
		    0100102a 15 00 00 00     ddw        15h
		
		 */

		addData();

		goTo(tool, program, addr("01001010"));

		nextByteValue();
		assertAddress("0100750e"); // a far away match

		goTo(tool, program, addr("0100101c"));
		nextByteValue();
		assertAddress("01001020");
		nextByteValue();
		assertAddress("01001024");
		nextByteValue();
		assertAddress("01006a02");

		toggleDirection();

		goTo(tool, program, addr("01001024"));
		nextByteValue();
		assertAddress("01001020");
		nextByteValue();
		assertAddress("0100101c");
		nextByteValue();
		assertAddress("0100101c"); // no more matching bytes
	}

	@Test
	public void testSearchNotBytesValue_Data() throws Exception {

		/*
		 
		 	01001010 52 65 67 69     ddw        69676552h
		    01001014 00              ??         00h
		    01001015 00              ??         00h
		    01001016 64 00 6f 00     ddw        6F0064h
		    0100101a 77              ??         77h    w
		    0100101b 00              ??         00h
		    0100101c 43 68 6f 6f     ddw        6F6F6843h
		    01001020 43 68 6f 6f     ddw        6F6F6843h
		    01001024 43 68 6f 6f     ddw        6F6F6843h
		    01001028 00              ??         00h
		    01001029 00              ??         00h
		    0100102a 15 00 00 00     ddw        15h
		
		 */

		addData();

		negateSearch();

		goTo(tool, program, addr("01001010"));

		nextByteValue();
		assertAddress("01001014");
		nextByteValue();
		assertAddress("01001016");
		nextByteValue();
		assertAddress("0100101a");

		goTo(tool, program, addr("0100101c"));
		nextByteValue();
		assertAddress("01001020");

		goTo(tool, program, addr("01001024"));
		nextByteValue();
		assertAddress("01001028");
		nextByteValue();
		assertAddress("0100102a");

		toggleDirection();

		nextByteValue();
		assertAddress("01001029");
		nextByteValue();
		assertAddress("01001024");
		nextByteValue();
		assertAddress("01001020");

		goTo(tool, program, addr("01001015"));
		nextByteValue();
		assertAddress("01001010");
	}

	@Test
	public void testSearchAllTypesBookmark() throws Exception {

		addBookmark("0100100c", BookmarkType.ERROR);
		addBookmark("0100101c", BookmarkType.INFO);
		addBookmark("0100101e", BookmarkType.WARNING);

		selectBookmarkType(NextPreviousBookmarkAction.ALL_BOOKMARK_TYPES);

		assertAddress("01001000");
		nextBookmark();
		assertAddress("0100100c");
		nextBookmark();
		assertAddress("0100101c");
		nextBookmark();
		assertAddress("0100101e");

		toggleDirection();

		nextBookmark();
		assertAddress("0100101c");
		nextBookmark();
		assertAddress("0100100c");
	}

	@Test
	public void testSearchNotBookmark() throws Exception {

		addBookmark("0100100c", BookmarkType.ERROR);
		addBookmark("0100101c", BookmarkType.INFO);
		addBookmark("0100101e", BookmarkType.WARNING);

		selectBookmarkType(NextPreviousBookmarkAction.ALL_BOOKMARK_TYPES);

		negateSearch();

		assertAddress("01001000");
		nextBookmark();
		assertAddress("0100100d");
		nextBookmark();
		assertAddress("0100101d");
		nextBookmark();
		assertAddress("0100101f");

		toggleDirection();

		nextBookmark();
		assertAddress("0100101d");
		nextBookmark();
		assertAddress("0100101b");
	}

	@Test
	public void testOffcutBookmarkForwardAndBackward() throws Exception {

		addBookmark("01001000", BookmarkType.INFO);
		addBookmark("01001004", BookmarkType.INFO);
		addBookmark("01001006", BookmarkType.INFO); // offcut
		addBookmark("0100101e", BookmarkType.INFO);

		selectBookmarkType(NextPreviousBookmarkAction.ALL_BOOKMARK_TYPES);

		assertAddress("01001000");
		nextBookmark();
		assertAddress("01001004");
		nextBookmark();
		assertAddress("0100101e");

		toggleDirection();

		nextBookmark();
		assertAddress("01001004");
		nextBookmark();
		assertAddress("01001000");
	}

	@Test
	public void testBookmarksOffcutInStructures() throws Exception {

		addBookmark("01001000", BookmarkType.INFO);
		addBookmark("01001004", BookmarkType.INFO);
		addBookmark("0100100d", BookmarkType.INFO);
		addBookmark("01001010", BookmarkType.INFO);
		addBookmark("01001015", BookmarkType.INFO);
		addBookmark("01001020", BookmarkType.INFO);

		StructureDataType struct = new StructureDataType("Test", 0);
		struct.add(new DWordDataType());
		struct.add(new DWordDataType());
		struct.add(new DWordDataType());
		assertEquals(12, struct.getLength());
		applyCmd(program, new CreateDataCmd(addr("0100100c"), struct));

		selectBookmarkType(NextPreviousBookmarkAction.ALL_BOOKMARK_TYPES);

		assertAddress("01001000");
		nextBookmark();
		assertAddress("01001004");
		nextBookmark();
		assertAddress("0100100c");
		nextBookmark();
		assertAddress("01001010");
		nextBookmark();
		assertAddress("01001014");
		nextBookmark();
		assertAddress("01001020");

		toggleDirection();

		nextBookmark();
		assertAddress("01001014");
		nextBookmark();
		assertAddress("01001010");
		nextBookmark();
		assertAddress("0100100c");
		nextBookmark();
		assertAddress("01001004");
	}

	@Test
	public void testSearchErrorBookmark() throws Exception {

		clearExisingBookmarks();

		// add more to our current set
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		addCmd.add(new BookmarkEditCmd(addr("01001110"), BookmarkType.ERROR, "Cat1a", "Cmt1A"));
		addCmd.add(new BookmarkEditCmd(addr("01001118"), BookmarkType.NOTE, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01001120"), BookmarkType.ERROR, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01001130"), BookmarkType.ERROR, "Cat1b", "Cmt1C"));
		addCmd.add(new BookmarkEditCmd(addr("01001140"), BookmarkType.ERROR, "Cat1b", "Cmt1D"));
		addCmd.add(new BookmarkEditCmd(addr("01001143"), BookmarkType.WARNING, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01001150"), BookmarkType.ERROR, "Cat2a", "Cmt2E"));
		addCmd.add(new BookmarkEditCmd(addr("01001154"), BookmarkType.INFO, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01001160"), BookmarkType.ERROR, "Cat2b", "Cmt2F"));
		applyCmd(program, addCmd);

		selectBookmarkType(BookmarkType.ERROR);

		assertAddress("01001000");
		nextBookmark();
		assertAddress("01001110");

		nextBookmark();
		assertAddress("01001120");

		nextBookmark();
		assertAddress("01001130");

		nextBookmark();
		assertAddress("01001140");

		nextBookmark();
		assertAddress("01001150");

		nextBookmark();
		assertAddress("01001160");

		nextBookmark();
		assertAddress("01001160");

		toggleDirection();

		nextBookmark();
		assertAddress("01001150");

		nextBookmark();
		assertAddress("01001140");

		nextBookmark();
		assertAddress("01001130");

		nextBookmark();
		assertAddress("01001120");

		nextBookmark();
		assertAddress("01001110");

		nextBookmark();
		assertAddress("01001110");
	}

	@Test
	public void testSearchNotErrorBookmark() throws Exception {

		clearExisingBookmarks();

		addBookmark("01001110", BookmarkType.ERROR);
		addBookmark("01001118", BookmarkType.NOTE);
		addBookmark("01001120", BookmarkType.ERROR);
		addBookmark("01001130", BookmarkType.ERROR);
		addBookmark("01001140", BookmarkType.WARNING);
		addBookmark("01001143", BookmarkType.INFO);

		selectBookmarkType(BookmarkType.ERROR);

		negateSearch();

		assertAddress("01001000");
		nextBookmark();
		assertAddress("01001118");

		nextBookmark();
		assertAddress("01001140");

		nextBookmark();
		assertAddress("01001143");

		toggleDirection();

		nextBookmark();
		assertAddress("01001140");

		nextBookmark();
		assertAddress("01001118");
	}

	@Test
	public void testSearchWarningBookmark() throws Exception {

		assertAddress("01001000");
		clearExisingBookmarks();

		// add more to our current set
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		addCmd.add(new BookmarkEditCmd(addr("01003e2c"), BookmarkType.WARNING, "Cat1a", "Cmt1A"));
		addCmd.add(new BookmarkEditCmd(addr("01003e2e"), BookmarkType.NOTE, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01003e30"), BookmarkType.WARNING, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01003e32"), BookmarkType.WARNING, "Cat1b", "Cmt1C"));
		addCmd.add(new BookmarkEditCmd(addr("01003e38"), BookmarkType.WARNING, "Cat1b", "Cmt1D"));
		addCmd.add(new BookmarkEditCmd(addr("01003e3a"), BookmarkType.WARNING, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01003e40"), BookmarkType.ANALYSIS, "Cat2a", "Cmt2E"));
		addCmd.add(new BookmarkEditCmd(addr("01003e41"), BookmarkType.INFO, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("01003e43"), BookmarkType.WARNING, "Cat2b", "Cmt2F"));
		applyCmd(program, addCmd);

		selectBookmarkType(BookmarkType.WARNING);

		nextBookmark();
		assertAddress("01003e2c");

		nextBookmark();
		assertAddress("01003e30");

		nextBookmark();
		assertAddress("01003e32");

		nextBookmark();
		assertAddress("01003e38");

		nextBookmark();
		assertAddress("01003e3a");

		nextBookmark();
		assertAddress("01003e43");

		nextBookmark();
		assertAddress("01003e43");

		toggleDirection();

		nextBookmark();
		assertAddress("01003e3a");

		nextBookmark();
		assertAddress("01003e38");

		nextBookmark();
		assertAddress("01003e32");

		nextBookmark();
		assertAddress("01003e30");

		nextBookmark();
		assertAddress("01003e2c");

		nextBookmark();
		assertAddress("01003e2c");
	}

	@Test
	public void testSearchCustomBobBookmark() throws Exception {

		assertAddress("01001000");
		Icon bookmarkBobIcon = Icons.ADD_ICON; // arbitrary icon

		BookmarkType bob = bookmarkManager.defineType("BOB", bookmarkBobIcon, Palette.YELLOW, 0);

		String typeString = bob.getTypeString();

		// add more to our current set
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		addCmd.add(new BookmarkEditCmd(addr("0100529b"), typeString, "Cat1a", "Cmt1A"));
		addCmd.add(new BookmarkEditCmd(addr("0100529d"), BookmarkType.NOTE, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("0100529e"), typeString, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("010052a1"), typeString, "Cat1b", "Cmt1C"));
		addCmd.add(new BookmarkEditCmd(addr("010052a3"), BookmarkType.WARNING, "Cat1b", "Cmt1D"));
		addCmd.add(new BookmarkEditCmd(addr("010052a4"), typeString, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("010052a6"), BookmarkType.ANALYSIS, "Cat2a", "Cmt2E"));
		addCmd.add(new BookmarkEditCmd(addr("010052a7"), typeString, "Cat2b", "Cmt2F"));
		applyCmd(program, addCmd);

		selectBookmarkType("Custom");

		nextBookmark();
		assertAddress("0100529b");

		nextBookmark();
		assertAddress("0100529e");

		nextBookmark();
		assertAddress("010052a1");

		nextBookmark();
		assertAddress("010052a4");

		nextBookmark();
		assertAddress("010052a7");

		nextBookmark();
		assertAddress("010052a7");

		toggleDirection();

		nextBookmark();
		assertAddress("010052a4");

		nextBookmark();
		assertAddress("010052a1");

		nextBookmark();
		assertAddress("0100529e");

		nextBookmark();
		assertAddress("0100529b");

		nextBookmark();
		assertAddress("0100529b");
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void addBookmark(String addrString, String type) {
		applyCmd(program, new BookmarkEditCmd(addr(addrString), type, "Cat1a", "Cmt1A"));
	}

	private void assertStartsWith(String expected, String actual) {
		assertTrue("startsWith expected: \"" + expected + "\", got: \"" + actual + "\"",
			actual.startsWith(expected));
	}

	private void assertAddress(String addrString) {
		assertEquals(addr(addrString), cb.getCurrentAddress());
	}

	private void assertAddress(Address addr) {
		assertEquals(addr, cb.getCurrentAddress());
	}

	private void toggleDirection() {
		performAction(direction, cb.getProvider(), true);
	}

	private void nextInstruction() {
		performAction(nextInstruction, cb.getProvider(), true);
	}

	private void nextData() {
		performAction(nextData, cb.getProvider(), true);
	}

	private void nextUndefined() {
		performAction(nextUndefined, cb.getProvider(), true);
	}

	private void nextLabel() {
		performAction(nextLabel, cb.getProvider(), true);
	}

	private void negateSearch() {
		performAction(invert, cb.getProvider(), true);
	}

	private void nextBookmark() throws Exception {
		performAction(nextBookmark, cb.getProvider(), true);
		waitForSwing();
		waitForTasks();
	}

	private void nextByteValue() {
		performAction(nextByteValue, cb.getProvider(), true);
	}

	private void selectBookmarkType(final String bookmarkType) {
		runSwing(() -> nextBookmark.setCurrentActionStateByUserData(bookmarkType));

		ActionState<String> currentState = nextBookmark.getCurrentState();
		assertEquals("Unable to set bookmark type to " + bookmarkType, bookmarkType,
			currentState.getUserData());
	}

	private Address addInstructions(String addr) throws Exception {

		Address address = program.getAddressFactory().getAddress(addr);
		tx(program, () -> {
			// these bytes create a couple instructions in x86
			Memory memory = program.getMemory();
			memory.setBytes(address, new byte[] { 0x55, (byte) 0x8b, (byte) 0xec });

			AddressSet set = new AddressSet(address, address.add(4));
			DisassembleCommand cmd = new DisassembleCommand(set, set);
			cmd.applyTo(program);
		});

		return address;
	}

	private void clearExisingBookmarks() throws Exception {
		tx(program, () -> {
			BookmarkManager bm = program.getBookmarkManager();
			AddressSet set = new AddressSet(program.getMemory());
			bm.removeBookmarks(set, TaskMonitor.DUMMY);
		});
	}

}
