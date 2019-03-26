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
package ghidra.app.plugin.core.compositeeditor;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.data.*;

public class StructureEditorUnlockedDnD4Test extends AbstractStructureEditorTest {

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		env.showTool();
	}

	protected void init(Structure dt, Category cat) {
		super.init(dt, cat, false);
		runSwing(() -> {
//				model.setLocked(false);
		});
//		assertTrue(!model.isLocked());
	}

	@Test
	public void testDragNDropAddFirstMiddleLast() throws Exception {
		init(complexStructure, pgmTestCat);
		DataType dt;
		int num = model.getNumComponents();

		dt = programDTM.getDataType("/word");
		assertNotNull(dt);
		assertEquals(325, model.getLength());

		// Replacing undefined .
		addAtPoint(dt, 0, 3);
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(DataType.DEFAULT));
		assertEquals("word doesn't fit.", model.getStatus());

		dt = programDTM.getDataType("/char");
		assertNotNull(dt);
		addAtPoint(dt, 0, 3);
		assertEquals(dt.getLength(), model.getComponent(0).getLength());
		assertEquals(325, model.getLength());

		// Replacing complexStructure * that is 4 bytes.
		addAtPoint(dt, 11, 3);
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(11).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(11).getLength());
		assertEquals(325, model.getLength());

		// Drop on blank line
		addAtPoint(dt, num, 3);
		num++;
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(num - 1).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(num - 1).getLength());
		assertEquals(326, model.getLength());
	}

	@Test
	public void testDragNDropInsertFirstMiddleLast() throws Exception {
		init(complexStructure, pgmTestCat);
		DataType dt;
		int num = model.getNumComponents();

		dt = programDTM.getDataType("/word");
		assertNotNull(dt);
		assertEquals(325, model.getLength());

		insertAtPoint(dt, 0, 3);
		num++;
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());
		assertEquals(327, model.getLength());

		insertAtPoint(dt, 10, 3);
		num++;
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(10).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(10).getLength());
		assertEquals(329, model.getLength());

		insertAtPoint(dt, num, 3);
		num++;
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(num - 1).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(num - 1).getLength());
		assertEquals(331, model.getLength());
	}

	@Test
	public void testDragNDropQWordOnFloat() throws Exception {
		init(simpleStructure, pgmBbCat);
		DataType dt;
		int num = model.getNumComponents();

		assertEquals(29, model.getLength());
		assertEquals("float", getDataType(5).getDisplayName());
		dt = programDTM.getDataType("/qword");
		assertNotNull(dt);

		addAtPoint(dt, 5, 3);

		assertEquals("qword doesn't fit.", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals("float", getDataType(5).getDisplayName());
		assertEquals(29, model.getLength());
	}

	@Test
	public void testDragNDropOnPointer() throws Exception {
		init(complexStructure, pgmTestCat);
		DataType dt;
		int num = model.getNumComponents();

		int origLen = model.getComponent(3).getLength();
		DataType origDt = getDataType(3);
		assertEquals("undefined *", origDt.getDisplayName());
		dt = programDTM.getDataType("/byte");
		assertNotNull(dt);

		addAtPoint(dt, 3, 3);

		assertEquals(num, model.getNumComponents());
		assertEquals("byte *", getDataType(3).getDisplayName());
		assertTrue(((Pointer) getDataType(3)).getDataType().isEquivalent(dt));
		assertEquals(origLen, model.getComponent(3).getLength());

		dt = programDTM.getDataType("/string");
		addAtPoint(dt, 3, 3);

		assertEquals(num, model.getNumComponents());
		assertEquals("string *", getDataType(3).getDisplayName());
		assertTrue(((Pointer) getDataType(3)).getDataType().isEquivalent(dt));
		assertEquals(origLen, model.getComponent(3).getLength());
	}

//	@Test
//	public void testDragNDropPointerOnQWord() throws Exception {
//		init(simpleStructure, pgmBbCat);
//
//		DataType origDt = getDataType(4);
//		assertEquals("qword", origDt.getDisplayName());
//		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer16");
//		assertNotNull(dt);
//		assertEquals(29, model.getLength());
//		assertEquals(8, model.getNumComponents());
//
//		addAtPoint(dt, 4, 3);
//
//		assertEquals(14, model.getNumComponents());
//		assertEquals("qword *", getDataType(4).getDisplayName());
//		assertTrue(((Pointer) getDataType(4)).getDataType().isEquivalent(origDt));
//		assertEquals(2, model.getComponent(4).getLength());
//		assertEquals(2, getDataType(4).getLength());
//		assertEquals(29, model.getLength());
//		assertEquals(14, model.getNumComponents());
//	}

	@Test
	public void testDragNDropPointerOnPointer() throws Exception {
		init(complexStructure, pgmTestCat);
		int num = model.getNumComponents();

		DataType origDt = getDataType(6);
		assertEquals("simpleStructure *", origDt.getDisplayName());
		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer");
		assertNotNull(dt);

		addAtPoint(dt, 6, 3);
		assertEquals(num, model.getNumComponents());
		assertEquals("simpleStructure * *", getDataType(6).getDisplayName());
		assertTrue(((Pointer) getDataType(6)).getDataType().isEquivalent(origDt));
		assertEquals(4, model.getComponent(6).getLength());
		assertEquals(4, getDataType(6).getLength());
	}

	@Test
	public void testDragNDropInsertPointerOnPointer() throws Exception {
		init(complexStructure, pgmTestCat);
		int num = model.getNumComponents();

		DataType origDt = getDataType(6);
		assertEquals("simpleStructure *", origDt.getDisplayName());
		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer16");
		assertNotNull(dt);

		insertAtPoint(dt, 6, 3);

		assertEquals(num + 1, model.getNumComponents());
		assertEquals("pointer16", getDataType(6).getDisplayName());
		assertEquals("simpleStructure *", getDataType(7).getDisplayName());
		assertTrue(getDataType(7).isEquivalent(origDt));
		assertTrue(getDataType(6).isEquivalent(dt));
		assertEquals(2, model.getComponent(6).getLength());
		assertEquals(4, model.getComponent(7).getLength());
		assertEquals(2, getDataType(6).getLength());
		assertEquals(4, getDataType(7).getLength());
	}

	@Test
	public void testDragNDropInsertToContiguous() throws Exception {
		init(complexStructure, pgmTestCat);

		DataType dt = programDTM.getDataType("/word");
		int num = model.getNumComponents();
		DataType dt3 = getDataType(3);
		DataType dt4 = getDataType(4);
		DataType dt5 = getDataType(5);
		DataType dt6 = getDataType(6);
		DataType dt15 = getDataType(15);
		setSelection(new int[] { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 });
		insertAtPoint(dt, 6, 0);
		checkSelection(new int[] { 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15 });
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(11, model.getNumSelectedComponentRows());
		assertEquals(dt3, getDataType(3));
		assertEquals(dt4, getDataType(4));
		assertEquals(dt5, getDataType(5));
		assertTrue(dt.isEquivalent(getDataType(6)));
		assertEquals(dt6, getDataType(7));
		assertEquals(dt15, getDataType(16));
	}

	@Test
	public void testDragNDropAddToContiguous() throws Exception {
		init(complexStructure, pgmTestCat);

		DataType dt = programDTM.getDataType("/word");
		int len = model.getLength();
		DataType dt3 = getDataType(3);
		DataType dt15 = getDataType(15);
		setSelection(new int[] { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 });// 39 bytes
		addAtPoint(dt, 5, 0);
		checkSelection(
			new int[] { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 });
		assertEquals(32, model.getNumComponents());
		assertEquals(20, model.getNumSelectedComponentRows());
		assertTrue(dt3.isEquivalent(getDataType(3)));
		assertTrue(dt.isEquivalent(getDataType(4)));
		assertEquals(dt15, getDataType(24));
		assertEquals(len, model.getLength());
	}

	@Test
	public void testDragNDropInsertToNonContiguous() throws Exception {
		init(complexStructure, pgmTestCat);

		DataType dt = programDTM.getDataType("/dword");
		int num = model.getNumComponents();
		int len = model.getLength();
		DataType dt3 = getDataType(3);
		DataType dt4 = getDataType(4);
		DataType dt5 = getDataType(5);
		DataType dt8 = getDataType(8);
		DataType dt9 = getDataType(9);
		DataType dt10 = getDataType(10);
		DataType dt15 = getDataType(15);
		setSelection(new int[] { 4, 5, 6, 7, 8, 11, 12, 13, 14 });
		insertAtPoint(dt, 5, 0);
		checkSelection(new int[] { 4, 6, 7, 8, 9, 12, 13, 14, 15 });
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(9, model.getNumSelectedComponentRows());
		assertEquals(dt3, getDataType(3));
		assertEquals(dt4, getDataType(4));
		assertTrue(dt.isEquivalent(getDataType(5)));
		assertEquals(dt5, getDataType(6));
		assertEquals(dt8, getDataType(9));
		assertEquals(dt9, getDataType(10));
		assertEquals(dt10, getDataType(11));
		assertEquals(dt15, getDataType(16));
		assertEquals(len + 4, model.getLength());
	}

	@Test
	public void testDragNDropAddToNonContiguous() throws Exception {
		init(complexStructure, pgmTestCat);

		DataType dt = programDTM.getDataType("/dword");
		int len = model.getLength();
		DataType dt3 = getDataType(3);
		DataType dt9 = getDataType(9);
		DataType dt10 = getDataType(10);
		DataType dt11 = getDataType(11);
		DataType dt12 = getDataType(12);
		DataType dt13 = getDataType(13);
		DataType dt15 = getDataType(15);
		setSelection(new int[] { 4, 5, 6, 7, 8, 11, 12, 13, 14 });
		addAtPoint(dt, 5, 0);
		checkSelection(new int[] { 4, 5, 6, 7, 8, 9, 12, 13, 14, 15 });
		assertEquals(24, model.getNumComponents());
		assertEquals(10, model.getNumSelectedComponentRows());
		assertEquals(dt3, getDataType(3));
		assertTrue(dt.isEquivalent(getDataType(4)));
		assertTrue(dt.isEquivalent(getDataType(5)));
		assertTrue(dt.isEquivalent(getDataType(6)));
		assertTrue(dt.isEquivalent(getDataType(7)));
		assertTrue(dt.isEquivalent(getDataType(8)));
		assertTrue(dt.isEquivalent(getDataType(9)));
		assertEquals(dt9, getDataType(10));
		assertEquals(dt10, getDataType(11));
		assertEquals(dt11, getDataType(12));
		assertEquals(dt12, getDataType(13));
		assertEquals(dt13, getDataType(14));
		assertEquals(dt15, getDataType(16));
		assertEquals(len, model.getLength());
	}

	@Test
	public void testDragNDropOnSelf() throws Exception {
		init(complexStructure, pgmTestCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		addAtPoint(complexStructure, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Data type \"complexStructure\" can't contain itself.", model.getStatus());
	}

	@Test
	public void testDragNDropSelfOnPointer() throws Exception {
		init(complexStructure, pgmTestCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		DataType dt6 = getDataType(6);
		assertEquals("", model.getStatus());
		addAtPoint(complexStructure, 6, 0);
		assertEquals(num, model.getNumComponents());
		assertTrue(!dt6.isEquivalent(getDataType(6)));
		assertEquals(((Pointer) getDataType(6)).getDataType(), model.viewComposite);
		assertEquals(len, model.getLength());
		assertEquals("", model.getStatus());
	}

	@Test
	public void testDragNDropFactory() throws Exception {
		init(complexStructure, pgmTestCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/PE");
		assertNotNull(dt);
		assertEquals("", model.getStatus());
		addAtPoint(dt, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Factory data types are not allowed in a composite data type.",
			model.getStatus());
	}

	@Test
	public void testDragNDropDynamic() throws Exception {
		init(complexStructure, pgmTestCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/GIF-Image");
		assertNotNull(dt);
		assertEquals("", model.getStatus());
		addAtPoint(dt, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Non-sizable Dynamic data types are not allowed in a composite data type.",
			model.getStatus());
	}

	@Test
	public void testDragNDropStructContainingEditType() throws Exception {
		init(simpleStructure, pgmBbCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		addAtPoint(complexStructure, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Data type \"complexStructure\" has \"simpleStructure\" within it.",
			model.getStatus());
	}

	@Test
	public void testDragNDropUnionContainingEditType() throws Exception {
		init(simpleStructure, pgmBbCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		addAtPoint(complexUnion, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Data type \"complexUnion\" has \"simpleStructure\" within it.",
			model.getStatus());
	}

//	public void testCancelDragNDropAddPointer() throws Exception {
//		NumberInputDialog dialog;
//		init(simpleStructure, pgmBbCat);
//		
//		DataType dt = plugin.getBuiltInDataTypesManager().findDataType("/pointer");
//		assertNotNull(dt);
//			
//		int num = model.getNumComponents();
//		int len = model.getLength();
//		assertEquals("", model.getStatus());
//		DataType dt2 = getDataType(2);
//		assertTrue(dt2.isEquivalent(new WordDataType()));
//		addAtPoint(dt,2,0);
//		dialog = (NumberInputDialog)env.waitForDialog(NumberInputDialog.class, 1000);
//		assertNotNull(dialog);
//		cancelInput(dialog);
//		dialog.dispose();
//		dialog = null;
//		assertEquals(num, model.getNumComponents());
//		assertEquals(len, model.getLength());
//		assertEquals(getDataType(2), dt2);
//		assertEquals(2, getDataType(2).getLength());
//		assertEquals(2, model.getComponent(2).getLength());
//	}

	@Test
	public void testDragNDropAddPointer() throws Exception {
		init(simpleStructure, pgmBbCat);

		int num = model.getNumComponents();
		assertEquals("", model.getStatus());
		assertTrue(getDataType(7).isEquivalent(CharDataType.dataType));

		addAtPoint(PointerDataType.dataType, 7, 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(32, model.getLength());
		assertEquals("pointer", getDataType(7).getDisplayName());
		assertNull(((Pointer) getDataType(7)).getDataType());
		assertEquals(4, getDataType(7).getLength());
		assertEquals(4, model.getComponent(7).getLength());

		addAtPoint(StringDataType.dataType, 7, 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(32, model.getLength());
		assertEquals("string *", getDataType(7).getDisplayName());
		assertTrue(((Pointer) getDataType(7)).getDataType().isEquivalent(StringDataType.dataType));
		assertEquals(4, getDataType(7).getLength());
		assertEquals(4, model.getComponent(7).getLength());

		addAtPoint(PointerDataType.dataType, 7, 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(32, model.getLength());
		assertEquals("string * *", getDataType(7).getDisplayName());
		assertTrue(((Pointer) getDataType(7)).getDataType().isEquivalent(
			new PointerDataType(StringDataType.dataType)));
		assertEquals(4, getDataType(7).getLength());
		assertEquals(4, model.getComponent(7).getLength());
	}

	@Test
	public void testDragNDropInsertPointer() throws Exception {
		init(simpleStructure, pgmBbCat);

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer");
		assertNotNull(dt);

		int num = model.getNumComponents();
		assertEquals("", model.getStatus());
		DataType dt2 = getDataType(2);
		assertTrue(dt2.isEquivalent(new WordDataType()));
		insertAtPoint(dt, 2, 0);
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(33, model.getLength());
		assertEquals("pointer", getDataType(2).getDisplayName());
		assertEquals(4, getDataType(2).getLength());
		assertEquals(4, model.getComponent(2).getLength());
		assertEquals(getDataType(3), dt2);
	}

	@Test
	public void testDragNDropInsertPointer8() throws Exception {
		init(simpleStructure, pgmBbCat);

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer8");
		assertNotNull(dt);

		int num = model.getNumComponents();
		assertEquals("", model.getStatus());
		DataType dt2 = getDataType(2);
		assertTrue(dt2.isEquivalent(new WordDataType()));
		insertAtPoint(dt, 2, 0);
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(30, model.getLength());
		assertEquals("pointer8", getDataType(2).getDisplayName());
		assertEquals(1, getDataType(2).getLength());
		assertEquals(1, model.getComponent(2).getLength());
		assertEquals(getDataType(3), dt2);
	}

	@Test
	public void testDragNDropInsertPointer16() throws Exception {
		init(simpleStructure, pgmBbCat);

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer16");
		assertNotNull(dt);

		int num = model.getNumComponents();
		assertEquals("", model.getStatus());
		DataType dt2 = getDataType(2);
		assertTrue(dt2.isEquivalent(new WordDataType()));
		insertAtPoint(dt, 2, 0);
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(31, model.getLength());
		assertEquals("pointer16", getDataType(2).getDisplayName());
		assertEquals(2, getDataType(2).getLength());
		assertEquals(2, model.getComponent(2).getLength());
		assertEquals(getDataType(3), dt2);
	}

	@Test
	public void testDragNDropInsertPointer32() throws Exception {
		init(simpleStructure, pgmBbCat);

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer32");
		assertNotNull(dt);

		int num = model.getNumComponents();
		assertEquals("", model.getStatus());
		DataType dt2 = getDataType(2);
		assertTrue(dt2.isEquivalent(new WordDataType()));
		insertAtPoint(dt, 2, 0);
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(33, model.getLength());
		assertEquals("pointer32", getDataType(2).getDisplayName());
		assertEquals(4, getDataType(2).getLength());
		assertEquals(4, model.getComponent(2).getLength());
		assertEquals(getDataType(3), dt2);
	}

	@Test
	public void testDragNDropInsertPointer64() throws Exception {
		init(simpleStructure, pgmBbCat);

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer64");
		assertNotNull(dt);

		int num = model.getNumComponents();
		assertEquals("", model.getStatus());
		DataType dt2 = getDataType(2);
		assertTrue(dt2.isEquivalent(new WordDataType()));
		insertAtPoint(dt, 2, 0);
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(37, model.getLength());
		assertEquals("pointer64", getDataType(2).getDisplayName());
		assertEquals(8, getDataType(2).getLength());
		assertEquals(8, model.getComponent(2).getLength());
		assertEquals(getDataType(3), dt2);
	}

}
