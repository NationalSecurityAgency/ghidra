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

import javax.swing.JDialog;
import javax.swing.JTextField;

import org.junit.Test;

import ghidra.program.model.data.*;

public class StructureEditorLockedDnDTest extends AbstractStructureEditorTest {

	protected void init(Structure dt, Category cat) {
		super.init(dt, cat, false);
		runSwing(() -> {
//				model.setLocked(true);
		});
//		assertTrue(model.isLocked());
	}

	@Test
	public void testDragNDropAddSameSize() throws Exception {
		init(complexStructure, pgmTestCat);
		DataType dt;

		assertEquals(23, model.getNumComponents());
		assertEquals(325, model.getLength());

		dt = programDTM.getDataType("/byte");
		assertNotNull(dt);
		addAtPoint(dt, 0, 0);
		assertEquals(23, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());
		assertEquals(325, model.getLength());
	}

	@Test
	public void testDragNDropConsumeAll() throws Exception {
		init(simpleStructure, pgmBbCat);
		DataType dt;
		runSwing(() -> {
			getModel().clearComponents(new int[] { 1, 2, 3 });
		});
		assertEquals(12, model.getNumComponents());
		assertEquals(29, model.getLength());

		dt = programDTM.getDataType("/double");
		assertNotNull(dt);
		addAtPoint(dt, 0, 0);
		assertEquals(5, model.getNumComponents());
		assertEquals(29, model.getLength());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());
	}

	@Test
	public void testDragNDropAddLargerNoFit() throws Exception {
		init(complexStructure, pgmTestCat);
		DataType dt;

		assertEquals(23, model.getNumComponents());
		assertEquals(325, model.getLength());

		dt = programDTM.getDataType("/double");
		DataType dt1 = getDataType(1);
		assertNotNull(dt);
		addAtPoint(dt, 1, 0);
		assertEquals(23, model.getNumComponents());
		assertTrue(getDataType(1).isEquivalent(dt1));
		assertEquals(dt1.getLength(), model.getComponent(1).getLength());
		assertEquals(325, model.getLength());
		assertEquals("double doesn't fit.", model.getStatus());
	}

	@Test
	public void testDragNDropAddSmaller() throws Exception {
		init(simpleStructure, pgmBbCat);
		DataType dt;

		assertEquals(8, model.getNumComponents());
		assertEquals(29, model.getLength());

		dt = programDTM.getDataType("/byte");
		DataType dt4 = getDataType(4);
		assertNotNull(dt);
		addAtPoint(dt, 3, 0);
		assertEquals(11, model.getNumComponents());
		assertTrue(getDataType(3).isEquivalent(dt));
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(5).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(6).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(dt4));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());
		assertEquals(29, model.getLength());
	}

	@Test
	public void testDragNDropAllowInsert() throws Exception {
		init(complexStructure, pgmTestCat);
		DataType dt;

		assertEquals(23, model.getNumComponents());
		assertEquals(325, model.getLength());
		DataType dt0 = getDataType(0);

		model.clearStatus();
		assertEquals("", model.getStatus());

		dt = programDTM.getDataType("/byte");
		assertNotNull(dt);
		insertAtPoint(dt, 0, 0);

		assertEquals(24, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertTrue(getDataType(1).isEquivalent(dt0));
		assertEquals(326, model.getLength());
		assertEquals("", model.getStatus());

		model.clearStatus();
		assertEquals("", model.getStatus());

		DataType dt6 = getDataType(6);
		dt = programDTM.getDataType("/double");
		assertNotNull(dt);
		insertAtPoint(dt, 6, 0);
		assertEquals(25, model.getNumComponents());
		assertTrue(getDataType(7).isEquivalent(dt6));
		assertEquals(334, model.getLength());
		assertEquals("", model.getStatus());

		model.clearStatus();
		assertEquals("", model.getStatus());

		final DataType dt3 = programDTM.getDataType("/undefined *32");
		DataType dt1 = getDataType(1);
		assertNotNull(dt3);
		insertAtPoint(dt3, 1, 0);
		assertEquals(26, model.getNumComponents());
		assertTrue(getDataType(2).isEquivalent(dt1));
		assertEquals(4, model.getComponent(1).getLength());
		assertEquals(338, model.getLength());
		assertEquals("", model.getStatus());

		model.clearStatus();
		assertEquals("", model.getStatus());

		final DataType dt4 = programDTM.getDataType("/string");
		assertNotNull(dt4);

		assertNotNull(dt4);
		insertAtPoint(dt4, 0, 0);

		JDialog dialog =
			waitForJDialog(env.getTool().getToolFrame(), "Enter Number", DEFAULT_WINDOW_TIMEOUT);
		assertNotNull(dialog);
		JTextField textField = findComponent(dialog, JTextField.class);
		triggerText(textField, "3");
		pressButtonByText(dialog, "OK");

		waitForPostedSwingRunnables();
		assertEquals(27, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt4));
		assertEquals(341, model.getLength());
		assertEquals("", model.getStatus());
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

	@Test
	public void testDragNDropPointerOnByte() throws Exception {
		init(simpleStructure, pgmBbCat);
		int num = model.getNumComponents();

		DataType origDt = getDataType(1);
		assertEquals("byte", origDt.getDisplayName());

		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/pointer");
		assertNotNull(dt);

		addAtPoint(dt, 1, 3);// Default 4-byte pointer does not fit
		assertEquals("byte", getDataType(1).getDisplayName());

		dt = builtInDTM.getDataType("/pointer8");
		assertNotNull(dt);

		addAtPoint(dt, 1, 3);

//		dialog = (NumberInputDialog)env.waitForWindow(NumberInputDialog.class, 1000);
//		assertNotNull(dialog);
//		okInput(dialog, 2);
//			
//		dialog = (NumberInputDialog)env.waitForWindow(NumberInputDialog.class, 1000);
//		assertNotNull(dialog);
//		okInput(dialog, 1);
//			
//		dialog.dispose();
//		dialog = null;

		assertEquals(num, model.getNumComponents());
		assertEquals("pointer8", getDataType(1).getDisplayName());
		assertNull(((Pointer) getDataType(1)).getDataType());
		assertEquals(1, model.getComponent(1).getLength());
		assertEquals(1, getDataType(1).getLength());
	}

	@Test
	public void testDragNDropPointerOnPointer() throws Exception {
		init(complexStructure, pgmTestCat);
		int num = model.getNumComponents();

		DataType origDt = getDataType(6);
		assertEquals("simpleStructure *", origDt.getDisplayName());
		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/pointer");
		assertNotNull(dt);

		addAtPoint(dt, 6, 3);
		assertEquals(num, model.getNumComponents());
		assertEquals("simpleStructure * *", getDataType(6).getDisplayName());
		assertTrue(((Pointer) getDataType(6)).getDataType().isEquivalent(origDt));
		assertEquals(4, model.getComponent(6).getLength());
		assertEquals(4, getDataType(6).getLength());
	}

//	public void testDragNDropInsertPointerOnPointer() throws Exception {
//		NumberInputDialog dialog;
//		init(complexStructure, pgmTestCat);
//		int num = model.getNumComponents();
//		
//		DataType origDt = getDataType(6);
//		assertEquals("simpleStructure *", origDt.getDisplayName());
//		final DataType dt = programDTM.findDataType("/pointer");
//		assertNotNull(dt);
//		
//		insertAtPoint(dt,6,3);
//		dialog = (NumberInputDialog)env.waitForWindow(NumberInputDialog.class, 1000);
//		assertNotNull(dialog);
//		okInput(dialog, 2);
//		dialog.dispose();
//		dialog = null;
//
//		assertEquals(num+1, model.getNumComponents());
//		assertEquals("Pointer", getDataType(6).getDisplayName());
//		assertEquals("simpleStructure *", getDataType(7).getDisplayName());
//		assertTrue(getDataType(7).isEquivalent(origDt));
//		assertTrue(getDataType(6).isEquivalent(dt));
//		assertEquals(2, model.getComponent(6).getLength());
//		assertEquals(4, model.getComponent(7).getLength());
//		assertEquals(-1, getDataType(6).getLength());
//		assertEquals(-1, getDataType(7).getLength());
//	}

//	public void testDragNDropInsertToContiguous() throws Exception {
//		init(complexStructure, pgmTestCat);
//		
//		DataType dt = programDTM.findDataType("/word");
//		int num = model.getNumComponents();
//		DataType dt3 = getDataType(3);
//		DataType dt4 = getDataType(4);
//		DataType dt5 = getDataType(5);
//		DataType dt6 = getDataType(6);
//		DataType dt15 = getDataType(15);
//		setSelection(new int[] {4,5,6,7,8,9,10,11,12,13,14});
//		insertAtPoint(dt,6,0);
//		checkSelection(new int[] {4,5,7,8,9,10,11,12,13,14,15});
//		assertEquals(num+1, model.getNumComponents());
//		assertEquals(11, model.getNumSelectedComponents());
//		assertEquals(dt3, getDataType(3));
//		assertEquals(dt4, getDataType(4));
//		assertEquals(dt5, getDataType(5));
//		assertTrue(dt.isEquivalent(getDataType(6)));
//		assertEquals(dt6, getDataType(7));
//		assertEquals(dt15, getDataType(16));
//	}

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

//	public void testDragNDropInsertToNonContiguous() throws Exception {
//		init(complexStructure, pgmTestCat);
//		
//		DataType dt = programDTM.findDataType("/dword");
//		int num = model.getNumComponents();
//		int len = model.getLength();
//		DataType dt3 = getDataType(3);
//		DataType dt4 = getDataType(4);
//		DataType dt5 = getDataType(5);
//		DataType dt6 = getDataType(6);
//		DataType dt8 = getDataType(8);
//		DataType dt9 = getDataType(9);
//		DataType dt10 = getDataType(10);
//		DataType dt15 = getDataType(15);
//		setSelection(new int[] {4,5,6,7,8,11,12,13,14});
//		insertAtPoint(dt,5,0);
//		checkSelection(new int[] {4,6,7,8,9,12,13,14,15});
//		assertEquals(num+1, model.getNumComponents());
//		assertEquals(9, model.getNumSelectedComponents());
//		assertEquals(dt3, getDataType(3));
//		assertEquals(dt4, getDataType(4));
//		assertTrue(dt.isEquivalent(getDataType(5)));
//		assertEquals(dt5, getDataType(6));
//		assertEquals(dt8, getDataType(9));
//		assertEquals(dt9, getDataType(10));
//		assertEquals(dt10, getDataType(11));
//		assertEquals(dt15, getDataType(16));
//		assertEquals(len+4, model.getLength());
//	}

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
		addAtPoint(complexStructure, 1, 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(!model.getStatus().equals(""));
	}

	@Test
	public void testDragNDropOnSelfAllSelected() throws Exception {
		init(simpleStructure, pgmBbCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		setSelection(new int[] { 0, 1, 2, 3, 4, 5, 6, 7 });
		addAtPoint(simpleStructure, 1, 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Data type \"simpleStructure\" can't contain itself.", model.getStatus());
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
//		PointerSizeDialog dialog;
//		init(simpleStructure, pgmBbCat);
//		
//		DataType dt = plugin.getBuiltInDataTypesManager().findDataType("/Pointer");
//		assertNotNull(dt);
//			
//		int num = model.getNumComponents();
//		int len = model.getLength();
//		assertEquals("", model.getStatus());
//		DataType dt2 = getDataType(2);
//		assertTrue(dt2.isEquivalent(new WordDataType()));
//		addAtPoint(dt,2,0);
//		dialog = (PointerSizeDialog)env.waitForDialog(PointerSizeDialog.class, 1000);
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
		DataType dt2 = getDataType(2);
		assertTrue(dt2.isEquivalent(new WordDataType()));

		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/pointer");
		assertNotNull(dt);

		addAtPoint(dt, 2, 0);// Default 4-byte pointer does not fit
		assertEquals("word", getDataType(2).getDisplayName());

		dt = builtInDTM.getDataType("/pointer16");
		assertNotNull(dt);

		addAtPoint(dt, 2, 0);

		assertEquals(num, model.getNumComponents());
		assertEquals(29, model.getLength());
		assertEquals("pointer16", getDataType(2).getDisplayName());
		assertNull(((Pointer) getDataType(2)).getDataType());
		assertEquals(2, getDataType(2).getLength());
		assertEquals(2, model.getComponent(2).getLength());

		addAtPoint(WordDataType.dataType, 2, 0); // stack word onto pointer16 to produce word *

		assertEquals(num, model.getNumComponents());
		assertEquals(29, model.getLength());
		assertEquals("word *", getDataType(2).getDisplayName());
		assertTrue(((Pointer) getDataType(2)).getDataType().isEquivalent(dt2));
		assertEquals(2, getDataType(2).getLength());
		assertEquals(2, model.getComponent(2).getLength());

	}

	@Test
	public void testDragNDropAddPointerAndConsume() throws Exception {
		init(simpleStructure, pgmBbCat);

		runSwing(() -> model.clearComponent(3));

		assertEquals("", model.getStatus());
		assertEquals(11, model.getNumComponents());
		DataType dt2 = getDataType(2);
		assertTrue(dt2.isEquivalent(new WordDataType()));

		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/pointer");
		assertNotNull(dt);

		addAtPoint(dt, 2, 0);

		assertEquals(9, model.getNumComponents());
		assertEquals(29, model.getLength());
		assertEquals("pointer", getDataType(2).getDisplayName());
		assertNull(((Pointer) getDataType(2)).getDataType());
		assertEquals(4, getDataType(2).getLength());
		assertEquals(4, model.getComponent(2).getLength());

		addAtPoint(WordDataType.dataType, 2, 0); // stack word onto pointer to produce word *

		assertEquals(9, model.getNumComponents());
		assertEquals(29, model.getLength());
		assertEquals("word *", getDataType(2).getDisplayName());
		assertTrue(((Pointer) getDataType(2)).getDataType().isEquivalent(dt2));
		assertEquals(4, getDataType(2).getLength());
		assertEquals(4, model.getComponent(2).getLength());
	}

	@Test
	public void testDragNDropNoInsertPointer() throws Exception {
		init(simpleStructure, pgmBbCat);

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer");
		assertNotNull(dt);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		DataType dt2 = getDataType(2);
		assertTrue(dt2.isEquivalent(new WordDataType()));

		insertAtPoint(dt, 2, 0);

		assertEquals("", model.getStatus());
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(len + 4, model.getLength());
		assertEquals("pointer", getDataType(2).getDisplayName());
		assertTrue(getDataType(2).isEquivalent(new PointerDataType()));
		assertEquals(dt2, getDataType(3));
	}

	@Test
	public void testDragNDropNoInsertSizedPointer() throws Exception {
		init(simpleStructure, pgmBbCat);

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer32");
		assertNotNull(dt);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		DataType dt2 = getDataType(2);
		assertTrue(dt2.isEquivalent(new WordDataType()));

		insertAtPoint(dt, 2, 0);

		assertEquals("", model.getStatus());
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(len + 4, model.getLength());
		assertEquals("pointer32", getDataType(2).getDisplayName());
		assertTrue(getDataType(2).isEquivalent(new Pointer32DataType()));
		assertEquals(dt2, getDataType(3));
	}

}
