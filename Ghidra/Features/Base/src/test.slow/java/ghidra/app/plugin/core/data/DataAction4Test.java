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
package ghidra.app.plugin.core.data;

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.dialogs.NumberInputDialog;
import generic.test.category.NightlyCategory;
import ghidra.app.SampleLocationGenerator;
import ghidra.app.plugin.core.compositeeditor.StructureEditorProvider;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.util.BytesFieldLocation;

@Category(NightlyCategory.class)
public class DataAction4Test extends AbstractDataActionTest {

	@Test
	public void testNotepadLocations() {

		Set<DockingActionIf> actions;

		program.addConsumer(this); // allow program to survive close
		try {
			closeProgram();

			actions = getActionsByOwner(tool, plugin.getName());
			assertEquals(ACTION_COUNT, actions.size());
			checkActions(actions, false, "Start");

			openProgram();
		}
		finally {
			program.release(this);
		}

		SampleLocationGenerator locGen = new SampleLocationGenerator(program);
		locGen.generateLocations(this);

		closeProgram();

		actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkActions(actions, false, "Start");
	}

	@Test
	public void testByte() {

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(DEFINE_BYTE, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkOnDefined(actions, ByteDataType.class);

		undo(program);

		actions = getActionsByOwner(tool, plugin.getName());
		checkOnUndefined(actions);

		gotoLocation(0x010069f2);
		checkOnUndefined(actions);

		gotoLocation(0x01006a00);
		checkOnUndefined(actions);

		doAction(RECENTLY_USED, true);
		checkOnDefined(actions, ByteDataType.class);

		makeSelection(0x01006a00, 0x01006a12);
		checkOnDefined(actions, ByteDataType.class);

		doAction(DEFINE_BYTE, true);
		checkDataType(0x01006a00, 0x01006a12, ByteDataType.class, 19, 0);

	}

	@Test
	public void testWord() {

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(DEFINE_WORD, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkOnDefined(actions, WordDataType.class);

		gotoLocation(0x010069f0);
		checkOnUndefined(actions);

		gotoLocation(0x010069f2);
		checkOnDefined(actions, WordDataType.class);

		gotoLocation(0x01006a00);
		checkOnUndefined(actions);

		doAction(RECENTLY_USED, true);
		checkOnDefined(actions, WordDataType.class);

		makeSelection(0x01006a00, 0x01006a12);
		checkOnDefined(actions, WordDataType.class);

		doAction(DEFINE_WORD, true);
		checkDataType(0x01006a00, 0x01006a12, WordDataType.class, 10, 0);
	}

	@Test
	public void testDWord() {

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(DEFINE_DWORD, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkOnDefined(actions, DWordDataType.class);

		gotoLocation(0x010069f0);
		checkOnUndefined(actions);

		gotoLocation(0x010069f2);
		checkOnDefined(actions, DWordDataType.class);

		gotoLocation(0x01006a00);
		checkOnUndefined(actions);

		doAction(RECENTLY_USED, true);
		checkOnDefined(actions, DWordDataType.class);

		makeSelection(0x01006a00, 0x01006a12);
		checkOnDefined(actions, DWordDataType.class);

		doAction(DEFINE_DWORD, true);
		checkDataType(0x01006a00, 0x01006a12, DWordDataType.class, 5, 0);
	}

	@Test
	public void testQWord() {

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(DEFINE_QWORD, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkOnDefined(actions, QWordDataType.class);

		gotoLocation(0x010069f0);
		checkOnUndefined(actions);

		gotoLocation(0x010069f2);
		checkOnDefined(actions, QWordDataType.class);

		gotoLocation(0x01006a00);
		checkOnUndefined(actions);

		doAction(RECENTLY_USED, true);
		checkOnDefined(actions, QWordDataType.class);

		makeSelection(0x01006a00, 0x01006a12);
		checkOnDefined(actions, QWordDataType.class);

		doAction(DEFINE_QWORD, true);
		checkDataType(0x01006a00, 0x01006a12, QWordDataType.class, 3, 0);
	}

	@Test
	public void testFloat() {

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(DEFINE_FLOAT, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkOnDefined(actions, FloatDataType.class);

		gotoLocation(0x010069f0);
		checkOnUndefined(actions);

		gotoLocation(0x010069f2);
		checkOnDefined(actions, FloatDataType.class);

		gotoLocation(0x01006a00);
		checkOnUndefined(actions);

		doAction(RECENTLY_USED, true);
		checkOnDefined(actions, FloatDataType.class);

		makeSelection(0x01006a00, 0x01006a12);
		checkOnDefined(actions, FloatDataType.class);

		doAction(DEFINE_FLOAT, true);
		checkDataType(0x01006a00, 0x01006a12, FloatDataType.class, 5, 0);
	}

	@Test
	public void testDouble() {

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(DEFINE_DOUBLE, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkOnDefined(actions, DoubleDataType.class);

		gotoLocation(0x010069f0);
		checkOnUndefined(actions);

		gotoLocation(0x010069f2);
		checkOnDefined(actions, DoubleDataType.class);

		gotoLocation(0x01006a00);
		checkOnUndefined(actions);

		doAction(RECENTLY_USED, true);
		checkOnDefined(actions, DoubleDataType.class);

		makeSelection(0x01006a00, 0x01006a12);
		checkOnDefined(actions, DoubleDataType.class);

		doAction(DEFINE_DOUBLE, true);
		checkDataType(0x01006a00, 0x01006a12, DoubleDataType.class, 3, 0);
	}

	@Test
	public void testCharCycle() {

		// Char cycle action on Undefined data

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(CYCLE_CHAR_STRING_UNICODE, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkOnDefined(actions, CharDataType.class);

		gotoLocation(0x010069f0);
		checkOnUndefined(actions);

		gotoLocation(0x010069f2);
		checkOnDefined(actions, CharDataType.class);

		gotoLocation(0x01006a00);
		checkOnUndefined(actions);

		// Repeat as recently used and run full cycle

		doAction(RECENTLY_USED, true);
		checkOnDefined(actions, CharDataType.class);

		doAction(CYCLE_CHAR_STRING_UNICODE, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, StringDataType.class);

		doAction(CYCLE_CHAR_STRING_UNICODE, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, UnicodeDataType.class);

		doAction(CYCLE_CHAR_STRING_UNICODE, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, CharDataType.class);

		clearLocation(0x01006a00);
		checkOnUndefined(actions);

		// Char cycle on selection

		makeSelection(0x01006a00, 0x01006a0f);

		doAction(CYCLE_CHAR_STRING_UNICODE, true);
		checkDataType(0x01006a00, 0x01006a0f, CharDataType.class, 0x10, 0);

		doAction(CYCLE_CHAR_STRING_UNICODE, true);
		checkDataType(0x01006a00, 0x01006a0f, StringDataType.class, 1, 0);

		doAction(CYCLE_CHAR_STRING_UNICODE, true);
		checkDataType(0x01006a00, 0x01006a0f, UnicodeDataType.class, 1, 0);

		doAction(CYCLE_CHAR_STRING_UNICODE, true);
		checkDataType(0x01006a00, 0x01006a0f, CharDataType.class, 0x10, 0);

		clearSelection();
	}

	@Test
	public void testByteCycle() {

		// Byte cycle action on Undefined data

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkOnDefined(actions, ByteDataType.class);

		gotoLocation(0x010069f0);
		checkOnUndefined(actions);

		gotoLocation(0x010069f2);
		checkOnDefined(actions, ByteDataType.class);

		gotoLocation(0x01006a00);
		checkOnUndefined(actions);

		// Repeat as recently used and run full cycle

		doAction(RECENTLY_USED, true);
		checkOnDefined(actions, ByteDataType.class);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, WordDataType.class);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, DWordDataType.class);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, QWordDataType.class);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, ByteDataType.class);

		clearLocation(0x01006a00);
		checkOnUndefined(actions);

		// Byte cycle on selection

		makeSelection(0x01006a00, 0x01006a12);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		checkDataType(0x01006a00, 0x01006a12, ByteDataType.class, 19, 0);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		checkDataType(0x01006a00, 0x01006a12, WordDataType.class, 10, 0);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		checkDataType(0x01006a00, 0x01006a12, DWordDataType.class, 5, 0);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		checkDataType(0x01006a00, 0x01006a12, QWordDataType.class, 3, 0);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		checkDataType(0x01006a00, 0x01006a12, ByteDataType.class, 19, 0);

		clearSelection();

		// Test cycle when it does not fit

		gotoLocation(0x010069f0);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnUndefined(actions);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, ByteDataType.class);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, WordDataType.class);

		doAction(CYCLE_BYTE_WORD_DWORD_QWORD, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnUndefined(actions);

	}

	@Test
	public void testFloatCycle() {

		// Float cycle action on Undefined data

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(CYCLE_FLOAT_DOUBLE, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(ACTION_COUNT, actions.size());
		checkOnDefined(actions, FloatDataType.class);

		gotoLocation(0x010069f0);
		checkOnUndefined(actions);

		gotoLocation(0x010069f2);
		checkOnDefined(actions, FloatDataType.class);

		gotoLocation(0x01006a00);
		checkOnUndefined(actions);

		// Repeat as recently used and run full cycle

		doAction(RECENTLY_USED, true);
		checkOnDefined(actions, FloatDataType.class);

		doAction(CYCLE_FLOAT_DOUBLE, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, DoubleDataType.class);

		doAction(CYCLE_FLOAT_DOUBLE, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, FloatDataType.class);

		clearLocation(0x01006a00);
		checkOnUndefined(actions);

		// Byte cycle on selection

		makeSelection(0x01006a00, 0x01006a12);

		doAction(CYCLE_FLOAT_DOUBLE, true);
		checkDataType(0x01006a00, 0x01006a12, FloatDataType.class, 5, 0);

		doAction(CYCLE_FLOAT_DOUBLE, true);
		checkDataType(0x01006a00, 0x01006a12, DoubleDataType.class, 3, 0);

		doAction(CYCLE_FLOAT_DOUBLE, true);
		checkDataType(0x01006a00, 0x01006a12, FloatDataType.class, 5, 0);

		clearSelection();

		// Test cycle when it does not fit

		gotoLocation(0x010069ee);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnUndefined(actions);

		doAction(CYCLE_FLOAT_DOUBLE, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, FloatDataType.class);

		doAction(CYCLE_FLOAT_DOUBLE, true);
		actions = getActionsByOwner(tool, plugin.getName());
		checkOnUndefined(actions);

	}

	@Test
	public void testArrayOnLocation() throws Exception {

		// Create Undefined[0x20] array

		gotoLocation(0x010069f2);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(CREATE_ARRAY, false);

		final NumberInputDialog dlg1 = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull("Expected element count input dialog", dlg1);

		Runnable r = () -> dlg1.setInput(0x20);
		runSwing(r);
		waitForPostedSwingRunnables();

		pressButtonByText(dlg1, "OK");

		waitForPostedSwingRunnables();

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		checkOnArray(actions, null, 0x20);

		// Test action disablement on array element location

		BytesFieldLocation loc =
			new BytesFieldLocation(program, addr(0x010069f2), addr(0x010069f2), new int[] { 0 }, 0);
		locationGenerated(loc);

		// Create Byte[0x10] array

		gotoLocation(0x01006b00);
		assertTrue("Undefined data expected", !getContextData().isDefined());

		doAction(DEFINE_BYTE, true);

		doAction(CREATE_ARRAY, false);

		final NumberInputDialog dlg2 = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull("Expected element count input dialog", dlg2);

		r = () -> dlg2.setInput(0x10);
		runSwing(r);
		waitForPostedSwingRunnables();

		pressButtonByText(dlg2, "OK");

		waitForPostedSwingRunnables();

		actions = getActionsByOwner(tool, plugin.getName());
		checkOnArray(actions, new ByteDataType(), 0x10);

	}

	@Test
	public void testArrayOnSelection() {

		// Create Undefined[0x20] array

		makeSelection(0x01006a00, 0x01006a1f);
		//assertNull("No data expected", getContextData());

		doAction(CREATE_ARRAY, true);

		clearSelection();// Remove selection to allow array check to work

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		checkOnArray(actions, null, 0x20);

		// Create Byte[0x10] array

		makeSelection(0x01006b00, 0x01006b0f);
		//assertNull("No data expected", getContextData());

		doAction(DEFINE_BYTE, true);

		doAction(CREATE_ARRAY, true);

		clearSelection();// Remove selection to allow array check to work

		actions = getActionsByOwner(tool, plugin.getName());
		checkOnArray(actions, new ByteDataType(), 0x10);

	}

	@Test
	public void testRecentlyUsed() throws Exception {

		gotoLocation(0x01006c00);

		DockingActionIf recentlyUsedAction = getAction(tool, plugin.getName(), RECENTLY_USED);
		String caseName = "On Structure at: " + getCurrentLocation();
		checkAction(recentlyUsedAction, false, caseName);

		makeSelection(0x01006a00, 0x01006a1f);
		doCreateStructureAction();
		clearSelection();

		checkAction(recentlyUsedAction, true, caseName);
	}

	@Test
	public void testStructureCreateEdit() throws Exception {

		// Create structure (length = 0x20)

		makeSelection(0x01006a00, 0x01006a1f);
		//assertNull("No data expected", getContextData());

		doCreateStructureAction();

		clearSelection();

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		checkOnStructure(actions, 0x20);

		gotoLocation(0x01006c00);
		checkOnUndefined(actions);

		doAction(RECENTLY_USED, true);
		checkOnStructure(actions, 0x20);

		doAction(EDIT_DATA_TYPE, true);

		// Verify that structure editor is displayed (expected to be in a new window)
		ComponentProvider provider = waitForComponentProvider(StructureEditorProvider.class);
		assertNotNull("Unable to find structure editor provider", provider);
		assertEquals("Structure Editor - struct (sample)", provider.getTitle());
	}

	@Test
	public void testComplexStructureCreate() throws Exception {

		// Component A0: byte
		gotoLocation(0x01006a00);
		doAction(DEFINE_BYTE, true);
		checkOnDefined(null, ByteDataType.class);

		// Component A1: float
		gotoLocation(0x01006a01);
		doAction(DEFINE_FLOAT, true);
		checkOnDefined(null, FloatDataType.class);

		// Component A2: undefined byte

		// Component A3: byte[10]
		gotoLocation(0x01006a06);
		doAction(DEFINE_BYTE, true);
		checkOnDefined(null, ByteDataType.class);
		makeSelection(0x01006a06, 0x01006a0f);
		doAction(CREATE_ARRAY, true);

		// Create Structure A (Component B0)
		makeSelection(0x01006a00, 0x01006a0f);
		doCreateStructureAction();

		clearSelection();

		checkOnStructure(null, 16);

		// Component B1: byte[16]
		gotoLocation(0x01006a10);
		doAction(DEFINE_BYTE, true);
		checkOnDefined(null, ByteDataType.class);
		makeSelection(0x01006a10, 0x01006a1f);
		doAction(CREATE_ARRAY, true);

		// Create Structure B
		makeSelection(0x01006a00, 0x01006a1f);
		doCreateStructureAction();

		clearSelection();

		checkOnStructure(null, 32);
		Composite structB = (Composite) getContextData().getDataType();

		DataType dt = structB.getComponent(0).getDataType();
		assertTrue(Composite.class.isInstance(dt));
		Composite structA = (Composite) dt;

		dt = structB.getComponent(1).getDataType();
		assertTrue(Array.class.isInstance(dt));

		Array a = (Array) dt;
		assertTrue(ByteDataType.class.isInstance(a.getDataType()));
		assertEquals(16, a.getLength());

		dt = structA.getComponent(0).getDataType();
		assertTrue(ByteDataType.class.isInstance(dt));

		dt = structA.getComponent(1).getDataType();
		assertTrue(FloatDataType.class.isInstance(dt));

		dt = structA.getComponent(2).getDataType();
		assertTrue(DefaultDataType.class.isInstance(dt));

		dt = structA.getComponent(3).getDataType();
		assertTrue(Array.class.isInstance(dt));

		a = (Array) dt;
		assertTrue(ByteDataType.class.isInstance(a.getDataType()));
		assertEquals(10, a.getLength());

		gotoLocation(0x01006c00);
		checkOnUndefined(null);

		doAction(RECENTLY_USED, true);
		checkOnStructure(null, 32);
	}

	@Test
	public void testStructureModify() throws Exception {

		// Create structure (length = 0x20)

		makeSelection(0x01006a00, 0x01006a1f);
		//assertNull("No data expected", getContextData());

		doCreateStructureAction();

		// Remove selection to allow edit action
		clearSelection();

		// Expand structure
		cb.toggleOpen(getContextData());

		gotoLocation(0x01006a00, new int[] { 0 });

		doAction(DEFINE_BYTE, true);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, ByteDataType.class);

		gotoLocation(0x01006a01, new int[] { 1 });

		doAction(DEFINE_FLOAT, true);

		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, FloatDataType.class);

		Data pdata = getContextData().getParent();
		assertTrue(pdata.isStructure());
		Structure struct = (Structure) pdata.getDataType();
		assertEquals(0x20, struct.getLength());
		DataTypeComponent[] structComps = struct.getComponents();
		assertTrue(structComps[0].getDataType() instanceof ByteDataType);
		assertTrue(structComps[1].getDataType() instanceof FloatDataType);

	}

	@Test
	public void testStructureModifyInsideArray() throws Exception {

		// Create structure (length = 0x20)

		makeSelection(0x01006a00, 0x01006a1f);
		//assertNull("No data expected", getContextData());

		doCreateStructureAction();
		clearSelection();

		Data structData = getContextData();
		assertNotNull(structData);
		assertTrue(structData.isStructure());
		DataType structDt = structData.getDataType();

		doAction(CREATE_ARRAY, false);

		final NumberInputDialog dlg1 = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull("Expected element count input dialog", dlg1);

		Runnable r = () -> dlg1.setInput(5);
		runSwing(r);
		waitForPostedSwingRunnables();

		pressButtonByText(dlg1, "OK");

		waitForPostedSwingRunnables();

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		checkOnArray(actions, structDt, 5);

		// Expand structure
		cb.toggleOpen(getContextData());

		gotoLocation(0x01006a00, new int[] { 0 });

		// Expand structure
		cb.toggleOpen(getContextData());

		gotoLocation(0x01006a00, new int[] { 0, 0 });

		doAction(DEFINE_BYTE, true);

		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, ByteDataType.class);

		gotoLocation(0x01006a01, new int[] { 0, 1 });

		doAction(DEFINE_FLOAT, true);

		actions = getActionsByOwner(tool, plugin.getName());
		checkOnDefined(actions, FloatDataType.class);

		Data pdata = getContextData().getParent();
		assertNotNull(pdata);
		assertTrue(pdata.isStructure());
		Structure struct = (Structure) pdata.getDataType();
		assertEquals(0x20, struct.getLength());
		DataTypeComponent[] structComps = struct.getComponents();
		assertTrue(structComps[0].getDataType() instanceof ByteDataType);
		assertTrue(structComps[1].getDataType() instanceof FloatDataType);

		pdata = pdata.getParent();
		assertNotNull(pdata);
		assertTrue(pdata.isArray());
		assertEquals(5 * 0x20, pdata.getLength());

		assertNull(pdata.getParent());

	}

	@Test
	public void testString() throws Exception {

		// Test creating a string with just a starting point, no length
		gotoLocation(0x01006a02);
		doAction(DEFINE_STRING, true);
		checkOnDefined(null, StringDataType.class);

		Data d = getContextData();
		assertEquals("ChooseFontW", d.getValue());
		assertEquals("\"ChooseFontW\"", d.getDefaultValueRepresentation());

		// Test creating a fixed length string using a selection that contains null term chars
		clearLocation(0x01006a02);
		makeSelection(0x01006a02, 0x01006a1f);

		doAction(DEFINE_STRING, true);
		checkOnDefined(null, StringDataType.class);

		d = getContextData();
		assertEquals("ChooseFontW\0\u0015\0ReplaceTextW\0\0\u0004", d.getValue());
		assertEquals("\"ChooseFontW\\0\",15h,\"\\0ReplaceTextW\\0\\0\",04h",
			d.getDefaultValueRepresentation());

	}

	@Test
	public void testTerminatedCString() throws Exception {

		// Test creating a string with just a starting point, no length
		gotoLocation(0x01006a02);
		doAction(DEFINE_TERM_CSTRING, true);
		checkOnDefined(null, TerminatedStringDataType.class);

		Data d = getContextData();
		assertEquals("ChooseFontW", d.getValue());
		assertEquals("\"ChooseFontW\"", d.getDefaultValueRepresentation());

		clearLocation(0x01006a02);

		// Test creating strings using a selection that contains multiple strings.
		makeSelection(0x01006a02, 0x01006a1f);
		doAction(DEFINE_TERM_CSTRING, true);
		checkOnDefined(null, TerminatedStringDataType.class);

		d = getContextData();
		assertEquals(12, d.getLength());

		DataIterator dit = program.getListing().getData(addr(0x01006a02), true);
		d = checkNextData(dit, TerminatedStringDataType.class, 0x01006a02, 12);
		assertEquals("ChooseFontW", d.getValue());
		assertEquals("\"ChooseFontW\"", d.getDefaultValueRepresentation());

		d = checkNextData(dit, TerminatedStringDataType.class, 0x01006a0e, 2);
		assertEquals("15h", d.getDefaultValueRepresentation());

		d = checkNextData(dit, TerminatedStringDataType.class, 0x01006a10, 13);
		assertEquals("ReplaceTextW", d.getValue());
		assertEquals("\"ReplaceTextW\"", d.getDefaultValueRepresentation());

		d = checkNextData(dit, TerminatedStringDataType.class, 0x01006a1d, 1);
		assertEquals("", d.getValue());
		assertEquals("\"\"", d.getDefaultValueRepresentation());

		d = checkNextData(dit, TerminatedStringDataType.class, 0x01006a1e, 2);
		assertEquals("04h", d.getDefaultValueRepresentation());
	}

	@Test
	public void testUnicode() throws Exception {

		String actionName = getDataTypeAction("unicode");

		// Test creating a string with just a starting point, no length
		gotoLocation(0x01008018);
		doAction(actionName, true);
		checkOnDefined(null, UnicodeDataType.class);

		Data d = getContextData();
		assertEquals("Sample", d.getValue());
		assertEquals("u\"Sample\"", d.getDefaultValueRepresentation());

		clearLocation(0x01008018);

		// Test creating a fixed length string using a selection that contains null term chars
		// Select 0x1008014-0x1008025, which is a wchar16[2] garbage string followed by "Sample",0
		gotoLocation(0x01008014);
		makeSelection(0x01008014, 0x01008025);

		doAction(actionName, true);
		checkOnDefined(null, UnicodeDataType.class);

		d = getContextData();
		assertEquals("01h,00h,\"\\0Sample\"", d.getDefaultValueRepresentation());
		assertEquals("\1\0Sample", d.getValue());

	}

	@Test
	public void testTerminatedUnicode() throws Exception {

		String actionName = getDataTypeAction("TerminatedUnicode");

		// Test creating a string with just a starting point, no length
		gotoLocation(0x01008018);
		doAction(actionName, true);
		checkOnDefined(null, TerminatedUnicodeDataType.class);

		Data d = getContextData();
		assertEquals("Sample", d.getValue());
		assertEquals("u\"Sample\"", d.getDefaultValueRepresentation());

		clearLocation(0x01008018);

		// Test creating strings using a selection that contains multiple strings.
		// Select 0x1008014-0x1008025, which is a wchar16[2] garbage string followed by "Sample",0
		// and create as many strings as possible (ie. 2)
		gotoLocation(0x01008014);
		makeSelection(0x01008014, 0x01008025);

		doAction(actionName, true);
		checkOnDefined(null, TerminatedUnicodeDataType.class);

		DataIterator dit = program.getListing().getData(addr(0x01008014), true);

		// check for wchar16[2] garbage string
		d = checkNextData(dit, TerminatedUnicodeDataType.class, 0x01008014, 4);
		assertEquals(d.getLength(), 4);
		assertEquals("01h,00h", d.getDefaultValueRepresentation());
		assertEquals("\1", d.getValue());

		// check for "Sample" string
		d = checkNextData(dit, TerminatedUnicodeDataType.class, 0x01008018, 14);
		assertEquals("u\"Sample\"", d.getDefaultValueRepresentation());
		assertEquals("Sample", d.getValue());

	}

	@Test
	public void testAllArrayDataSettings() throws Exception {

		// create byte data from which byte arrays will be cerated

		gotoLocation(0x1006a02);
		doAction(DEFINE_BYTE, true);

		gotoLocation(0x100abeb);
		doAction(DEFINE_BYTE, true);

		manipulateAllSettings(false, false, false, CREATE_ARRAY);
	}

	@Test
	public void testAllArrayInStructDataSettings() throws Exception {

		// create byte data from which byte arrays will be cerated

		gotoLocation(0x1006a02);
		doAction(DEFINE_BYTE, true);

		gotoLocation(0x100abeb);
		doAction(DEFINE_BYTE, true);

		manipulateAllSettings(false, true, false, CREATE_ARRAY);
		manipulateAllSettings(true, true, true, CREATE_ARRAY);
	}
}
