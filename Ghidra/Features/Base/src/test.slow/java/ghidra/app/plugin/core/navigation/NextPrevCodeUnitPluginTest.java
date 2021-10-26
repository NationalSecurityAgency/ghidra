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

import java.awt.Color;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.bookmark.BookmarkEditCmd;
import ghidra.app.plugin.core.bookmark.BookmarkPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class NextPrevCodeUnitPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private DockingActionIf direction;
	private DockingActionIf nextInst;
	private DockingActionIf nextData;
	private DockingActionIf nextUndef;
	private DockingActionIf nextLabel;
	private DockingActionIf nextFunc;
	private DockingActionIf nextNonFunc;
	private MultiStateDockingAction<String> nextBookmark;
	private BookmarkManager bookmarkManager;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);
		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	@SuppressWarnings("unchecked")
	// we know that bookmarks is of type String
	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(NextPrevCodeUnitPlugin.class.getName());
		tool.addPlugin(BookmarkPlugin.class.getName());

		NextPrevCodeUnitPlugin p = getPlugin(tool, NextPrevCodeUnitPlugin.class);
		direction = getAction(p, "Toggle Search Direction");
		nextInst = getAction(p, "Next Instruction");
		nextData = getAction(p, "Next Data");
		nextUndef = getAction(p, "Next Undefined");
		nextLabel = getAction(p, "Next Label");
		nextFunc = getAction(p, "Next Function");
		nextNonFunc = getAction(p, "Next Non-Function");
		nextBookmark = (MultiStateDockingAction<String>) getAction(p, "Next Bookmark");
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void loadProgram(String programName) throws Exception {

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		builder.setName(programName);
		program = builder.getProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		builder.dispose();
		addrFactory = program.getAddressFactory();
		bookmarkManager = program.getBookmarkManager();
	}

	@Test
	public void testToggle() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		Icon upIcon = ResourceManager.loadImage("images/up.png");
		Icon downIcon = ResourceManager.loadImage("images/down.png");

		assertEquals(downIcon, direction.getToolBarData().getIcon());
		assertEquals("Go To Next Instruction", nextInst.getDescription());
		assertEquals("Go To Next Data", nextData.getDescription());
		assertEquals("Go To Next Undefined", nextUndef.getDescription());
		assertEquals("Go To Next Label", nextLabel.getDescription());
		assertEquals("Go To Next Function", nextFunc.getDescription());
		assertEquals("Go To Next Instruction Not In a Function", nextNonFunc.getDescription());
		assertEquals("Go To Next Bookmark: All Types", nextBookmark.getDescription());

		performAction(direction, cb.getProvider(), true);

		assertEquals(upIcon, direction.getToolBarData().getIcon());
		assertEquals("Go To Previous Instruction", nextInst.getDescription());
		assertEquals("Go To Previous Data", nextData.getDescription());
		assertEquals("Go To Previous Undefined", nextUndef.getDescription());
		assertEquals("Go To Previous Label", nextLabel.getDescription());
		assertEquals("Go To Previous Function", nextFunc.getDescription());
		assertEquals("Go To Previous Instruction Not In a Function", nextNonFunc.getDescription());
		assertEquals("Go To Previous Bookmark: All Types", nextBookmark.getDescription());

		performAction(direction, cb.getProvider(), true);

		assertEquals(downIcon, direction.getToolBarData().getIcon());
		assertEquals("Go To Next Instruction", nextInst.getDescription());
		assertEquals("Go To Next Data", nextData.getDescription());
		assertEquals("Go To Next Undefined", nextUndef.getDescription());
		assertEquals("Go To Next Label", nextLabel.getDescription());
		assertEquals("Go To Next Function", nextFunc.getDescription());
		assertEquals("Go To Next Instruction Not In a Function", nextNonFunc.getDescription());
		assertEquals("Go To Next Bookmark: All Types", nextBookmark.getDescription());
	}

	@Test
	public void testSearchInstruction() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("0x1001000"), cb.getCurrentAddress());
		performAction(nextInst, cb.getProvider(), true);
		assertEquals(addr("0x1002239"), cb.getCurrentAddress());
		performAction(nextInst, cb.getProvider(), true);
		assertEquals(addr("0x1002cf5"), cb.getCurrentAddress());

		performAction(direction, cb.getProvider(), true);
		performAction(nextInst, cb.getProvider(), true);
		assertEquals(addr("0x100294d"), cb.getCurrentAddress());
		performAction(nextInst, cb.getProvider(), true);

		// no more instructions, this is the last range
		assertEquals(addr("0x100294d"), cb.getCurrentAddress());
	}

	@Test
	public void testSearchData() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("0x1001000"), cb.getCurrentAddress());
		performAction(nextData, cb.getProvider(), true);
		assertEquals(addr("0x1001058"), cb.getCurrentAddress());
		performAction(nextData, cb.getProvider(), true);
		assertEquals(addr("0x1001080"), cb.getCurrentAddress());

		performAction(direction, cb.getProvider(), true);
		performAction(nextData, cb.getProvider(), true);
		assertEquals(addr("0x1001058"), cb.getCurrentAddress());
		performAction(nextData, cb.getProvider(), true);

	}

	@Test
	public void testSearchUndefined() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("0x1001000"), cb.getCurrentAddress());
		performAction(nextUndef, cb.getProvider(), true);
		assertEquals(addr("0x100100c"), cb.getCurrentAddress());
		performAction(nextUndef, cb.getProvider(), true);
		assertEquals(addr("0x100105c"), cb.getCurrentAddress());

		performAction(direction, cb.getProvider(), true);
		performAction(nextUndef, cb.getProvider(), true);
		assertEquals(addr("0x1001057"), cb.getCurrentAddress());
		performAction(nextUndef, cb.getProvider(), true);

		// no more undefined data, this is the last range
		assertEquals(addr("0x1001057"), cb.getCurrentAddress());
	}

	@Test
	public void testSearchLabel() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("0x1001000"), cb.getCurrentAddress());
		performAction(nextLabel, cb.getProvider(), true);
		assertEquals(addr("0x1001004"), cb.getCurrentAddress());
		performAction(nextLabel, cb.getProvider(), true);
		assertEquals(addr("0x1001008"), cb.getCurrentAddress());

		performAction(direction, cb.getProvider(), true);
		performAction(nextLabel, cb.getProvider(), true);
		assertEquals(addr("0x1001004"), cb.getCurrentAddress());
		performAction(nextLabel, cb.getProvider(), true);
		assertEquals(addr("0x1001000"), cb.getCurrentAddress());
		performAction(nextLabel, cb.getProvider(), true);

		// no more labels, this is the last range
		assertEquals(addr("0x1001000"), cb.getCurrentAddress());
	}

	@Test
	public void testSearchFunction() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("0x1001000"), cb.getCurrentAddress());
		performAction(nextFunc, cb.getProvider(), true);
		assertEquals(addr("0x100194b"), cb.getCurrentAddress());
		performAction(nextFunc, cb.getProvider(), true);
		assertEquals(addr("0x1001ae3"), cb.getCurrentAddress());

		performAction(direction, cb.getProvider(), true);
		performAction(nextFunc, cb.getProvider(), true);
		assertEquals(addr("0x100194b"), cb.getCurrentAddress());
		performAction(nextFunc, cb.getProvider(), true);

		// no more functions, this is the last range
		assertEquals(addr("0x100194b"), cb.getCurrentAddress());
	}

	@Test
	public void testSearchNonFunction() throws Exception {
		loadProgram("notepad");

		Address a1 = addInstructions("0x01006600");
		Address a2 = addInstructions("0x0100662a");

		showTool(tool);
		assertEquals(addr("0x1001000"), cb.getCurrentAddress());
		performAction(nextNonFunc, cb.getProvider(), true);
		assertEquals(a1, cb.getCurrentAddress());
		performAction(nextNonFunc, cb.getProvider(), true);
		assertEquals(a2, cb.getCurrentAddress());

		performAction(direction, cb.getProvider(), true);
		performAction(nextNonFunc, cb.getProvider(), true);
		assertEquals(addr("0x1006603"), cb.getCurrentAddress());
		performAction(nextNonFunc, cb.getProvider(), true);

		// no more functions, this is the last range
		assertEquals(addr("0x1006603"), cb.getCurrentAddress());
	}

	@Test
	public void testSearchAllTypesBookmark() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("01001000"), cb.getCurrentAddress());

		//
		// Setup:
		// 100c - error bookmark
		// 101c - info bookmark
		// 101e - warning bookmark
		//
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		addCmd.add(new BookmarkEditCmd(addr("0100100c"), BookmarkType.ERROR, "Cat1a", "Cmt1A"));
		addCmd.add(new BookmarkEditCmd(addr("0100101c"), BookmarkType.INFO, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("0100101e"), BookmarkType.WARNING, "Cat1a", "Cmt1B"));
		applyCmd(program, addCmd);

		selectBookmarkType(BookmarkType.ALL_TYPES);

		pressBookmark();
		assertEquals(addr("0100100c"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("0100101c"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("0100101e"), cb.getCurrentAddress());

		toggleDirection();

		pressBookmark();
		assertEquals(addr("0100101c"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("0100100c"), cb.getCurrentAddress());
	}

	@Test
	public void testOffcutBookmarkForwardAndBackward() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("01001000"), cb.getCurrentAddress());

		//
		// Setup:
		// 1000 - info bookmark
		// 1006 - offcut info bookmark
		// 101e - info bookmark
		//
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		addCmd.add(new BookmarkEditCmd(addr("01001000"), BookmarkType.INFO, "Cat1a", "Cmt1A"));
		addCmd.add(new BookmarkEditCmd(addr("01001004"), BookmarkType.INFO, "Cat1a", "Cmt1BC"));
		addCmd.add(new BookmarkEditCmd(addr("01001006"), BookmarkType.INFO, "Cat1a", "Cmt1B"));
		addCmd.add(new BookmarkEditCmd(addr("0100101e"), BookmarkType.INFO, "Cat1a", "Cmt1B"));
		applyCmd(program, addCmd);

		selectBookmarkType(BookmarkType.ALL_TYPES);

		pressBookmark();
		assertEquals(addr("01001004"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("0100101e"), cb.getCurrentAddress());

		toggleDirection();

		pressBookmark();
		assertEquals(addr("01001004"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("01001000"), cb.getCurrentAddress());
	}

	@Test
	public void testBookmarksOffcutInStructures() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("01001000"), cb.getCurrentAddress());

		//
		// Setup:
		// 1000 - info bookmark
		// 1006 - offcut info bookmark
		// 101e - info bookmark
		//
		CompoundCmd addCmd = new CompoundCmd("Add Bookmarks");
		addCmd.add(new BookmarkEditCmd(addr("01001000"), BookmarkType.INFO, "Cat1a", "A"));
		addCmd.add(new BookmarkEditCmd(addr("01001004"), BookmarkType.INFO, "Cat1a", "B"));
		addCmd.add(new BookmarkEditCmd(addr("0100100d"), BookmarkType.INFO, "Cat1a", "C"));
		addCmd.add(new BookmarkEditCmd(addr("01001010"), BookmarkType.INFO, "Cat1a", "C"));
		addCmd.add(new BookmarkEditCmd(addr("01001015"), BookmarkType.INFO, "Cat1a", "D"));
		addCmd.add(new BookmarkEditCmd(addr("01001020"), BookmarkType.INFO, "Cat1a", "E"));

		StructureDataType struct = new StructureDataType("Test", 0);
		struct.add(new DWordDataType());
		struct.add(new DWordDataType());
		struct.add(new DWordDataType());
		assertEquals(12, struct.getLength());

		addCmd.add(new CreateDataCmd(addr("0100100c"), struct));

		applyCmd(program, addCmd);

		selectBookmarkType(BookmarkType.ALL_TYPES);

		pressBookmark();
		assertEquals(addr("01001004"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("0100100c"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("01001010"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("01001014"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("01001020"), cb.getCurrentAddress());

		toggleDirection();

		pressBookmark();
		assertEquals(addr("01001014"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("01001010"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("0100100c"), cb.getCurrentAddress());
		pressBookmark();
		assertEquals(addr("01001004"), cb.getCurrentAddress());
	}

	@Test
	public void testErrorBookmark() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("01001000"), cb.getCurrentAddress());
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

		pressBookmark();
		assertEquals(addr("01001110"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001120"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001130"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001140"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001150"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001160"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001160"), cb.getCurrentAddress());

		toggleDirection();

		pressBookmark();
		assertEquals(addr("01001150"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001140"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001130"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001120"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001110"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01001110"), cb.getCurrentAddress());
	}

	@Test
	public void testWarningBookmark() throws Exception {
		loadProgram("notepad");
		showTool(tool);
		assertEquals(addr("01001000"), cb.getCurrentAddress());
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

		pressBookmark();
		assertEquals(addr("01003e2c"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e30"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e32"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e38"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e3a"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e43"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e43"), cb.getCurrentAddress());

		toggleDirection();

		pressBookmark();
		assertEquals(addr("01003e3a"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e38"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e32"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e30"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e2c"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("01003e2c"), cb.getCurrentAddress());
	}

	@Test
	public void testCustomBobBookmark() throws Exception {
		loadProgram("notepad");
		showTool(tool);

		assertEquals(addr("01001000"), cb.getCurrentAddress());
		ImageIcon bookmarkBobIcon =
			ResourceManager.loadImage("images/applications-engineering.png");

		BookmarkType bob = bookmarkManager.defineType("BOB", bookmarkBobIcon, Color.YELLOW, 0);

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

		pressBookmark();
		assertEquals(addr("0100529b"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("0100529e"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("010052a1"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("010052a4"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("010052a7"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("010052a7"), cb.getCurrentAddress());

		toggleDirection();

		pressBookmark();
		assertEquals(addr("010052a4"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("010052a1"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("0100529e"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("0100529b"), cb.getCurrentAddress());

		pressBookmark();
		assertEquals(addr("0100529b"), cb.getCurrentAddress());
	}

	private void toggleDirection() {
		performAction(direction, cb.getProvider(), true);
	}

	private void pressBookmark() throws Exception {
		performAction(nextBookmark, cb.getProvider(), true);
		waitForSwing();
		waitForTasks();
	}

	private void selectBookmarkType(final String bookmarkType) {
		runSwing(() -> nextBookmark.setCurrentActionStateByUserData(bookmarkType));

		ActionState<String> currentState = nextBookmark.getCurrentState();
		assertEquals("Unable to set bookmark type to " + bookmarkType, bookmarkType,
			currentState.getUserData());
	}

	private Address addInstructions(String addr) throws Exception {

		Address address = program.getAddressFactory().getAddress(addr);

		int txID = program.startTransaction("Add Test Instruction");
		try {
			// these bytes create a couple instructions in x86
			Memory memory = program.getMemory();
			memory.setBytes(address, new byte[] { 0x55, (byte) 0x8b, (byte) 0xec });

			AddressSet set = new AddressSet(address, address.add(4));
			DisassembleCommand cmd = new DisassembleCommand(set, set);
			cmd.applyTo(program);
		}
		finally {
			program.endTransaction(txID, true);
		}

		return address;
	}

	private void clearExisingBookmarks() throws Exception {
		int txID = program.startTransaction("Add Test Instruction");
		try {
			BookmarkManager bm = program.getBookmarkManager();
			AddressSet set = new AddressSet(program.getMemory());
			bm.removeBookmarks(set, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txID, true);
		}
	}

}
