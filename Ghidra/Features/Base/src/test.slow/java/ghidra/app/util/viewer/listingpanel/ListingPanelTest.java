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
package ghidra.app.util.viewer.listingpanel;

import static org.junit.Assert.*;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.*;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ListingPanelTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private Program program;
	private AddressFactory addrFactory;
	private AddressSpace space;
	private CodeViewerService cvs;
	private ListingModel listingModel;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);
		loadProgram("notepad");
		resetFormatOptions();
		cvs = tool.getService(CodeViewerService.class);
		listingModel = cvs.getListingModel();
	}

	private Layout getLayout(Address addr) {
		return listingModel.getLayout(addr, false);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private Address addr(long address) {
		return space.getAddress(address);
	}

	private void loadProgram(String programName) throws Exception {
		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
		space = addrFactory.getDefaultAddressSpace();

	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._X86, this);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".data", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		builder.applyDataType("0x1001000", PointerDataType.dataType, 4);
		builder.setBytes("0x1001008", "01 02 03 04");
		builder.createMemoryReference("1001100", "1001008", RefType.READ, SourceType.DEFAULT);
		builder.createLabel("0x1001008", "ADVAPI32.dll_RegQueryValueExW");
		builder.createExternalReference("0x1001008", "ADVAPI32.dll", "RegQueryValueExW", 0);

		builder.setBytes("1004772", "bf 00 01 00 00", true);
		builder.createMemoryReference("1004700", "1004777", RefType.DATA, SourceType.DEFAULT);
		return builder.getProgram();
	}

	@Test
	public void testGetLayout() {
//		env.showTool();
		assertNull(getLayout(addr(0)));
		Layout l = getLayout(addr(0x1001000));
		assertNotNull(l);
		assertEquals(6, l.getNumFields());

		assertNull(getLayout(addr(0x1001001)));
	}

	@Test
	public void testGetStringsFromLayout() {
		env.showTool();
		Layout l = getLayout(addr(0x1001008));

		int n = l.getNumFields();
		assertEquals(7, n);

		assertEquals("ADVAPI32.dll_RegQueryValueExW", l.getField(0).getText());
		assertEquals("XREF[1]: ", l.getField(1).getText());
		assertEquals("01001100(R)  ", l.getField(2).getText());
		assertEquals("01001008", l.getField(3).getText());
		assertEquals("01 02 03 04", l.getField(4).getText());
		assertEquals("addr", l.getField(5).getText());
		assertEquals("ADVAPI32.dll::RegQueryValueExW", l.getField(6).getText());
	}

	@Test
	public void testGetStringsFromLayout1() {
		env.showTool();
		Layout l = getLayout(addr(0x1004772));

		int n = l.getNumFields();
		assertEquals(4, n);

		assertEquals("01004772", l.getField(0).getText());
		assertEquals("bf 00 01 00 00", l.getField(1).getText());
		assertEquals("MOV", l.getField(2).getText());
		assertEquals("EDI,0x100", l.getField(3).getText());
	}

	@Test
	public void testProgramLocation1() {
		Layout l = getLayout(addr(0x1004772));

		ListingField f = (ListingField) l.getField(1);
		assertEquals("bf 00 01 00 00", f.getText());

		FieldFactory ff = f.getFieldFactory();
		RowColLocation rc = f.textOffsetToScreenLocation(3);
		ProgramLocation loc = ff.getProgramLocation(rc.row(), rc.col(), f);
		assertEquals(BytesFieldLocation.class, loc.getClass());
		BytesFieldLocation bfloc = (BytesFieldLocation) loc;
		assertEquals(1, bfloc.getByteIndex());

		rc = f.textOffsetToScreenLocation(13);
		assertEquals(1, rc.row());
		loc = ff.getProgramLocation(rc.row(), rc.col(), f);
		assertEquals(BytesFieldLocation.class, loc.getClass());
		bfloc = (BytesFieldLocation) loc;
		assertEquals(4, bfloc.getByteIndex());
	}

	@Test
	public void testProgramLocation2() {
		int id = program.startTransaction("test");
		Instruction inst = program.getListing().getInstructionAt(addr(0x1004772));
		String comment =
			"This is a very long comment. I want this sentence to wrap to the next line so that I can test wrapping.";
		inst.setComment(CodeUnit.EOL_COMMENT, comment);
		program.endTransaction(id, true);
		cb.updateNow();
		Layout l = getLayout(addr(0x1004772));
		env.showTool();

		ListingField f = (ListingField) l.getField(4);
		assertEquals(comment, f.getText());

		FieldFactory ff = f.getFieldFactory();
		RowColLocation rc = f.textOffsetToScreenLocation(3);
		ProgramLocation loc = ff.getProgramLocation(rc.row(), rc.col(), f);
		assertEquals(EolCommentFieldLocation.class, loc.getClass());
		EolCommentFieldLocation bfloc = (EolCommentFieldLocation) loc;
		assertEquals(0, bfloc.getRow());
		assertEquals(3, bfloc.getCharOffset());

		rc = f.textOffsetToScreenLocation(72);
		assertEquals(0, rc.row());
		loc = ff.getProgramLocation(rc.row(), rc.col(), f);
		assertEquals(EolCommentFieldLocation.class, loc.getClass());
		bfloc = (EolCommentFieldLocation) loc;
		assertEquals(0, bfloc.getRow());
		assertEquals(72, bfloc.getCharOffset());
	}

	@Test
	public void testProgramLocation3() {
		int id = program.startTransaction("test");
		Instruction inst = program.getListing().getInstructionAt(addr(0x1004772));
		String comment =
			"This is a very long comment. I want this sentence to wrap to the next line so that I can test wrapping.";
		inst.setComment(CodeUnit.EOL_COMMENT, comment);
		program.endTransaction(id, true);
		Options opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		opt.setBoolean("EOL Comments Field.Enable Word Wrapping", true);

		cb.updateNow();
		Layout l = getLayout(addr(0x1004772));
		env.showTool();

		ListingField f = (ListingField) l.getField(4);

		assertEquals(comment, f.getText());

		FieldFactory ff = f.getFieldFactory();
		RowColLocation rc = f.textOffsetToScreenLocation(3);
		ProgramLocation loc = ff.getProgramLocation(rc.row(), rc.col(), f);
		assertEquals(EolCommentFieldLocation.class, loc.getClass());
		EolCommentFieldLocation bfloc = (EolCommentFieldLocation) loc;
		assertEquals(0, bfloc.getRow());
		assertEquals(3, bfloc.getCharOffset());

		rc = f.textOffsetToScreenLocation(72);
		assertEquals(2, rc.row());
		loc = ff.getProgramLocation(rc.row(), rc.col(), f);
		assertEquals(EolCommentFieldLocation.class, loc.getClass());
		bfloc = (EolCommentFieldLocation) loc;
		assertEquals(0, bfloc.getRow());
		assertEquals(72, bfloc.getCharOffset());
	}

	@Test
	public void testProgramLocation4() {
		int id = program.startTransaction("test");
		Instruction inst = program.getListing().getInstructionAt(addr(0x1004772));
		String comment1 = "This is a very long comment.";
		String comment2 =
			"I want this sentence to wrap to the next line so that I can test wrapping.";
		String[] comments = new String[] { comment1, comment2 };
		inst.setCommentAsArray(CodeUnit.EOL_COMMENT, comments);
		program.endTransaction(id, true);
		Options opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		opt.setBoolean("EOL Comments Field.Enable Word Wrapping", true);

		cb.updateNow();
		Layout l = getLayout(addr(0x1004772));
		env.showTool();

		ListingField f = (ListingField) l.getField(4);
		assertEquals(comment1 + "  " + comment2, f.getText());

		FieldFactory ff = f.getFieldFactory();
		RowColLocation rc = f.textOffsetToScreenLocation(3);
		ProgramLocation loc = ff.getProgramLocation(rc.row(), rc.col(), f);
		assertEquals(EolCommentFieldLocation.class, loc.getClass());
		EolCommentFieldLocation bfloc = (EolCommentFieldLocation) loc;
		assertEquals(0, bfloc.getRow());
		assertEquals(3, bfloc.getCharOffset());

		rc = f.textOffsetToScreenLocation(72);
		assertEquals(2, rc.row());
		loc = ff.getProgramLocation(rc.row(), rc.col(), f);
		assertEquals(EolCommentFieldLocation.class, loc.getClass());
		bfloc = (EolCommentFieldLocation) loc;
		assertEquals(1, bfloc.getRow());
		assertEquals(42, bfloc.getCharOffset());
	}

	@Test
	public void testTextOffset() {
		int id = program.startTransaction("test");
		Instruction inst = program.getListing().getInstructionAt(addr(0x1004772));
		String comment1 = "This is a very long comment.";
		String comment2 =
			"I want this sentence to wrap to the next line so that I can test wrapping.";
		String[] comments = new String[] { comment1, comment2 };
		inst.setCommentAsArray(CodeUnit.EOL_COMMENT, comments);
		program.endTransaction(id, true);
//		Options opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
//		opt.putBoolean("test", "EOL Comments Field.Enable Word Wrapping", true);

		cb.updateNow();
		Layout l = getLayout(addr(0x1004772));
		env.showTool();

		ListingField f = (ListingField) l.getField(4);
		assertEquals(comment1 + " " + comment2, f.getText());

		int offset = f.screenLocationToTextOffset(1, 0);
		assertEquals("I want", f.getText().substring(offset, offset + 6));

	}

	@Test
	public void testListingDisplayListener() {
		showTool(tool);

		AtomicReference<AddressSetView> addresses = new AtomicReference<>();
		CodeViewerService cvs = tool.getService(CodeViewerService.class);
		cvs.addListingDisplayListener(new ListingDisplayListener() {
			@Override
			public void visibleAddressesChanged(AddressSetView visibleAddresses) {
				addresses.set(visibleAddresses);
			}
		});

		assertNull(addresses.get());
		cvs.goTo(new ProgramLocation(program, addr(0x1008000)), false);
		assertNotNull(addresses.get());
		assertTrue(addresses.get().contains(addr(0x1008000)));
		assertFalse(addresses.get().contains(addr(0x1001000)));

		cvs.goTo(new ProgramLocation(program, addr(0x1001000)), false);
		assertNotNull(addresses.get());
		assertFalse(addresses.get().contains(addr(0x1008000)));
		assertTrue(addresses.get().contains(addr(0x1001000)));

	}

	private void resetFormatOptions() {
		Options fieldOptions = cb.getFormatManager().getFieldOptions();
		List<String> names = fieldOptions.getOptionNames();

		for (String name : names) {
			if (!name.startsWith("Format Code")) {
				continue;
			}
			if (name.indexOf("Show ") >= 0 || name.indexOf("Flag ") >= 0) {
				fieldOptions.setBoolean(name, false);
			}
			else if (name.indexOf("Lines") >= 0) {
				fieldOptions.setInt(name, 0);
			}
		}
		waitForPostedSwingRunnables();
		cb.updateNow();
	}

}
