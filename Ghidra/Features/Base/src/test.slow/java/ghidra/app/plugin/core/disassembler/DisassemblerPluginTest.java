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
package ghidra.app.plugin.core.disassembler;

import static org.junit.Assert.*;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.clear.ClearPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.*;
import ghidra.test.*;

public class DisassemblerPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private DockingActionIf disassemblyAction;
	private DockingActionIf staticDisassemblyAction;

	public DisassemblerPluginTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);

		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(DisassemblerPlugin.class.getName());
		tool.addPlugin(ClearPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		DisassemblerPlugin dp = getPlugin(tool, DisassemblerPlugin.class);
		disassemblyAction = getAction(dp, "Disassemble");
		staticDisassemblyAction = getAction(dp, "Disassemble Static");
	}

	private void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testDisassemblyActionEnablement() throws Exception {
		assertTrue(!disassemblyAction.isEnabledForContext(getContext()));
		loadNotepad();
		showTool(tool);
		cb.updateNow();
		assertTrue(cb.goToField(addr("0x1001a00"), "Address", 0, 0));
		assertTrue(disassemblyAction.isEnabledForContext(getContext()));
		closeProgram();
		assertTrue(!disassemblyAction.isEnabledForContext(getContext()));
	}

	@Test
	public void testStopOnStop() throws Exception {
		loadNotepad();
		showTool(tool);
		clearAll();

		assertEquals(0, getInstructionCount());

		disassemble(addr("100294a"));
		assertEquals(4, getInstructionCount());

		assertTrue(cb.goToField(addr("100294d"), "Mnemonic", 0, 0));
		cb.updateNow();
		assertEquals("RET", cb.getCurrentFieldText());
	}

	@Test
	public void testStopOnData() throws Exception {
		loadNotepad();
		showTool(tool);

		clearAll();

		applyCmd(program, new CreateDataCmd(addr("0x100294c"), new ByteDataType()));
		assertEquals(0, getInstructionCount());

		disassemble(addr("100294a"));
		assertEquals(2, getInstructionCount());

		assertTrue(cb.goToField(addr("100294d"), "Mnemonic", 0, 0));
		cb.updateNow();
		assertEquals("??", cb.getCurrentFieldText());
	}

	@Test
	public void testStopOnOtherInstruction() throws Exception {
		loadNotepad();
		showTool(tool);

		clearAll();
		assertEquals(0, getInstructionCount());

		disassembleStatic(addr("100294c"));
		assertEquals(1, getInstructionCount());

		disassemble(addr("100294a"));
		assertEquals(3, getInstructionCount());

		// ensure that duplicate instruction is not marked
		assertEquals(0, program.getBookmarkManager().getBookmarks(addr("0x10063b0")).length);
	}

	@Test
	public void testInstructionConflict() throws Exception {
		loadNotepad();
		showTool(tool);

		clearAll();

		assertTrue(cb.goToField(addr("10028f0"), "Address", 0, 0));
		assertEquals(0, getInstructionCount());

		disassembleStatic(addr("10028f0"));
		assertEquals(1, getInstructionCount());

		disassemble(addr("0x10028eb"));
		assertEquals(2, getInstructionCount());

		// ensure bookmark for the conflict
		assertEquals(1, program.getBookmarkManager().getBookmarks(addr("0x10028ee")).length);
	}

	@Test
	public void testStopOnZeroInstructionRun() throws Exception {
		loadNotepad();

		showTool(tool);
		clearAll();

		disassemble(addr("1001010"));
		int count = Disassembler.MAX_REPEAT_PATTERN_LENGTH + 1;
		assertEquals(count, program.getListing().getNumInstructions());

		int txId = program.startTransaction("Set Bytes");
		try {
			Address addr = addr("1001040");
			for (int i = 0; i <= Disassembler.MAX_REPEAT_PATTERN_LENGTH + 4; i++) {
				program.getMemory().setShort(addr, (short) 0x1111);
				addr = addr.add(2);
			}
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertTrue(cb.goToField(addr("1001040"), "Address", 0, 0));
		performAction(disassemblyAction, cb.getProvider(), true);
		waitForBusyTool(tool);
		assertEquals(2 * count, program.getListing().getNumInstructions());
	}

	@Test
	public void testDisassmbleFollowsFlows() throws Exception {
		loadNotepad();

		showTool(tool);
		clearAll();
		assertEquals(0, getInstructionCount());

		disassemble(addr("10022e6"));
		assertEquals(486, getInstructionCount());

		undo(program);
		assertEquals(0, getInstructionCount());

		redo(program);
		assertEquals(486, getInstructionCount());
	}

	@Test
	public void testDisassmebleOnSelection() throws Exception {
		loadNotepad();

		showTool(tool);
		clearAll();
		cb.goToField(addr("0x100294c"), "Address", 0, 0, 0, true); // show the work area

		makeSelection(tool, program, addr("0x100294a"), addr("0x100294b"));

		assertEquals(0, getInstructionCount());

		disassemble(addr("0x100294c"));
		assertEquals(4, getInstructionCount());
	}

	@Test
	public void testDisassmebleOnSelectionWithMixOfAlreadyDisassmbledAreas() throws Exception {
		loadNotepad();
		Listing listing = program.getListing();

		showTool(tool);
		Address startAddr = addr("100285d");
		Address middleAddr = addr("1002865");
		Address endAddr = addr("1002875");
		cb.goToField(middleAddr, "Address", 0, 0, 0, true); // show the work area

		clear(startAddr);
		clear(middleAddr);
		clear(endAddr);

		assertNull(listing.getInstructionAt(startAddr));
		assertNull(listing.getInstructionAt(middleAddr));
		assertNull(listing.getInstructionAt(endAddr));

		makeSelection(tool, program, startAddr, endAddr);

		performAction(disassemblyAction, cb.getProvider(), true);
		waitForBusyTool(tool);
		assertNotNull(listing.getInstructionAt(startAddr));
		assertNotNull(listing.getInstructionAt(middleAddr));
		assertNotNull(listing.getInstructionAt(endAddr));

	}

	@Test
	public void testDisassembleDisjointSelection() throws Exception {
		loadNotepad();

		showTool(tool);
		clearAll();
		FieldPanel fp = cb.getFieldPanel();
		FieldSelection sel = new FieldSelection();
		cb.goToField(addr("1002949"), "Bytes", 0, 4);
		FieldLocation p1 = fp.getCursorLocation();
		cb.goToField(addr("100294c"), "Address", 0, 0);
		FieldLocation p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);

		cb.goToField(addr("1002d66"), "Address", 0, 0);
		p1 = fp.getCursorLocation();
		cb.goToField(addr("1002d6a"), "Address", 0, 0);
		p2 = fp.getCursorLocation();
		sel.addRange(p1, p2);

		setSelection(fp, sel);

		assertEquals(0, getInstructionCount());

		performAction(disassemblyAction, cb.getProvider(), true);
		waitForBusyTool(tool);
		assertEquals(10, getInstructionCount());
	}

	@Test
	public void testStaticDisassembly() throws Exception {
		assertTrue(!staticDisassemblyAction.isEnabledForContext(getContext()));
		loadNotepad();
		showTool(tool);

		clearAll();

		cb.goToField(addr("0x1002949"), "Address", 0, 0);
		assertTrue(staticDisassemblyAction.isEnabledForContext(getContext()));
		assertEquals(0, getInstructionCount());

		disassembleStatic(addr("1002949"));
		assertEquals(1, getInstructionCount());

		closeProgram();
		assertTrue(!staticDisassemblyAction.isEnabledForContext(getContext()));
	}

	@Test
	public void testStaticDisassemblySelection() throws Exception {
		loadNotepad();
		showTool(tool);

		clearAll();

		makeSelection(tool, program, addr("1002949"), addr("100294c"));

		disassembleStatic(addr("1002949"));
		assertEquals(4, getInstructionCount());
	}

	/*
	 * This method will verify that instructions are NOT allowed to overlap.
	 */
	@Test
	public void testOverlappingCodeUnits() throws Exception {
		loadNotepad();
		showTool(tool);
		clearAll();

		disassembleStatic(addr("0x010028f0"));
		disassembleStatic(addr("0x010028ee"));

		cb.goToField(addr("10028ee"), "Mnemonic", 0, 0);
		assertEquals("??", cb.getCurrentFieldText());
	}

	private void disassembleStatic(Address a) {
		doDisassemble(staticDisassemblyAction, a);
	}

	private void disassemble(Address a) {
		doDisassemble(disassemblyAction, a);
	}

	private void doDisassemble(DockingActionIf action, Address a) {
		cb.goToField(a, "Address", 0, 0);
		performAction(action, cb.getProvider(), true);
		waitForBusyTool(tool);
		program.flushEvents();
		cb.updateNow();
		waitForSwing();
	}

	private Instruction getInstruction(Address a) {
		return program.getListing().getInstructionAt(a);
	}

	private long getInstructionCount() {
		return program.getListing().getNumInstructions();
	}

	@Test
	public void testDelaySlot() throws Exception {
		loadToyProgram();
		showTool(tool);
		assertEquals(0, getInstructionCount());

		disassembleStatic(addr("110"));
		assertEquals(2, getInstructionCount());
		Instruction i1 = getInstruction(addr("110"));
		assertEquals(1, i1.getDelaySlotDepth());
		assertTrue(!i1.isInDelaySlot());

		Instruction i2 = getInstruction(addr("112"));
		assertEquals(0, i2.getDelaySlotDepth());
		assertTrue(i2.isInDelaySlot());

		undo(program);

		disassembleStatic(addr("112"));
		assertEquals(1, getInstructionCount());
		i2 = getInstruction(addr("112"));
		assertEquals(0, i2.getDelaySlotDepth());
		assertTrue(!i2.isInDelaySlot());

		disassembleStatic(addr("110"));
		assertEquals(2, getInstructionCount());

		i1 = getInstruction(addr("110"));
		assertEquals(1, i1.getDelaySlotDepth());
		assertTrue(!i1.isInDelaySlot());

		i2 = getInstruction(addr("112"));
		assertEquals(0, i2.getDelaySlotDepth());
		assertTrue(i2.isInDelaySlot());

		clear(addr("110"));
		assertEquals(0, getInstructionCount());

		undo(program);

		clear(addr("112"));
		assertEquals(0, getInstructionCount());

		clearAll();

		disassembleStatic(addr("112"));
		assertEquals(1, getInstructionCount());

		disassemble(addr("110"));
		assertTrue(getInstructionCount() > 2);
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void clearAll() throws Exception {
		DockingActionIf action = getAction(cb, "Select All");
		performAction(action, cb.getProvider(), true);
		ClearPlugin dp = getPlugin(tool, ClearPlugin.class);
		DockingActionIf clearAction = getAction(dp, "Clear Code Bytes");
		performAction(clearAction, cb.getProvider(), true);
		waitForBusyTool(tool);
		program.flushEvents();
		waitForSwing();

		clickMouse(cb.getFieldPanel(), 1, 0, 0, 1, 0);

		cb.updateNow();
	}

	private void loadNotepad() throws Exception {
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
		openProgramInTool();
	}

	private void loadToyProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("toy", true);
		builder.createMemory("test", "100", 0x100);
		builder.addBytesCallWithDelaySlot("110", "130");
		builder.addBytesFallthrough("114");
		program = builder.getProgram();
		openProgramInTool();
	}

	private void openProgramInTool() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();

		// Disable all analysis
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		setInstanceField("isEnabled", analysisMgr, Boolean.FALSE);
	}

	private ActionContext getContext() {
		ActionContext context = cb.getProvider().getActionContext(null);
		return context == null ? new ActionContext() : context;
	}

	private void setSelection(FieldPanel fp, FieldSelection sel) {
		fp.setSelection(sel);
		Class<?>[] argClasses = new Class<?>[] { EventTrigger.class };
		Object[] args = new Object[] { EventTrigger.GUI_ACTION };
		invokeInstanceMethod("notifySelectionChanged", fp, argClasses, args);
	}

	private void clear(Address addr) {
		applyCmd(program, new ClearCmd(new AddressSet(addr, addr)));
	}

}
