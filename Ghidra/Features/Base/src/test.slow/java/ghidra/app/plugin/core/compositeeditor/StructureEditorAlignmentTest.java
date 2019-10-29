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

import javax.swing.JRadioButton;
import javax.swing.JTextField;

import org.junit.Test;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite.AlignmentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.SourceType;

public class StructureEditorAlignmentTest extends AbstractStructureEditorTest {

	@Test
	public void testUnalignedStructure() {
		init(emptyStructure, pgmRootCat, false);

		assertTrue(structureModel.hasChanges());// initial unsaved empty structure
		assertTrue(structureModel.isValidName());// name should be valid
		assertEquals(structureModel.getTypeName(), "Structure");
		assertEquals(emptyStructure.getName(), structureModel.getCompositeName());
		assertEquals(emptyStructure.getDescription(), structureModel.getDescription());
		assertEquals(pgmRootCat.getCategoryPathName(),
			structureModel.getOriginalCategoryPath().getPath());
		assertEquals(0, structureModel.getNumComponents());// no components
		assertEquals(1, structureModel.getRowCount());// blank row
		assertIsInternallyAligned(false);
		assertPackingValue(Composite.NOT_PACKING);
		assertMinimumAlignmentType(AlignmentType.DEFAULT_ALIGNED);
		assertMinimumAlignmentValue(Composite.DEFAULT_ALIGNMENT_VALUE);
		assertLength(0);
		assertActualAlignment(1);
		assertEquals(0, structureModel.getNumSelectedComponentRows());
		assertEquals(1, structureModel.getNumSelectedRows());
		checkSelection(new int[] { 0 });

//		// Check enablement.
//		CompositeEditorAction[] pActions = provider.getActions();
//		for (int i = 0; i < pActions.length; i++) {
//			if ((pActions[i] instanceof FavoritesAction)
//			|| (pActions[i] instanceof CycleGroupAction)
//			|| (pActions[i] instanceof EditFieldAction)
//			|| (pActions[i] instanceof PointerAction)
//			|| (pActions[i] instanceof HexNumbersAction)) {
//				checkEnablement(pActions[i], true);
//			}
//			else {
//				checkEnablement(pActions[i], false);
//			}
//		}

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, 5, "char[5]", arrayDt, "", "");
		assertLength(10);
		assertActualAlignment(1);
	}

	@Test
	public void testDefaultAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		waitForSwing();

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, 5, "char[5]", arrayDt, "", "");
		assertLength(10);
		assertActualAlignment(1);

		pressButtonByName(getPanel(), "Internally Aligned");

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 8, 5, "char[5]", arrayDt, "", "");
		assertLength(16);
		assertActualAlignment(4);
	}

	@Test
	public void testEnablementDefaultAlignedStructure() throws Exception {
		emptyStructure.setInternallyAligned(true);
		init(emptyStructure, pgmRootCat, false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		// Check enablement.
		CompositeEditorTableAction[] pActions = provider.getActions();
		for (int i = 0; i < pActions.length; i++) {
			if ((pActions[i] instanceof FavoritesAction) ||
				(pActions[i] instanceof CycleGroupAction) ||
				(pActions[i] instanceof EditFieldAction) ||
				(pActions[i] instanceof InsertUndefinedAction) ||
				(pActions[i] instanceof PointerAction) ||
				(pActions[i] instanceof HexNumbersAction) || (actions[i] instanceof ApplyAction)) {
				checkEnablement(pActions[i], true);
			}
			else {
				checkEnablement(pActions[i], false);
			}
		}

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 8, 5, "char[5]", arrayDt, "", "");
		assertLength(16);
		assertActualAlignment(4);
	}

	@Test
	public void testMachineAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		waitForSwing();

		pressButtonByName(getPanel(), "Internally Aligned");
		pressButtonByName(getPanel(), "Machine Minimum Alignment");

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 8, 5, "char[5]", arrayDt, "", "");
		assertLength(16);
		assertActualAlignment(8);
	}

	@Test
	public void testByValueAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		waitForSwing();

		pressButtonByName(editorPanel, "Internally Aligned");
		JTextField minAlignField =
			(JTextField) getInstanceField("minAlignValueTextField", editorPanel);
		assertNotNull(minAlignField);
		JRadioButton byValueMinAlignButton =
			(JRadioButton) getInstanceField("byValueMinAlignButton", editorPanel);
		assertNotNull(byValueMinAlignButton);
		pressButton(byValueMinAlignButton);
		assertEquals("4", minAlignField.getText());

		assertEquals(false, structureModel.viewComposite.isDefaultAligned());
		assertEquals(false, structureModel.viewComposite.isMachineAligned());
		assertEquals(4, structureModel.getMinimumAlignment());

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 8, 5, "char[5]", arrayDt, "", "");
		assertLength(16);
		assertActualAlignment(4);
	}

	@Test
	public void testByValue1AlignedStructure() throws Exception {
		checkByValueAlignedStructure(1, 4, 16);
	}

	@Test
	public void testByValue2AlignedStructure() throws Exception {
		checkByValueAlignedStructure(2, 4, 16);
	}

	@Test
	public void testByValue4AlignedStructure() throws Exception {
		checkByValueAlignedStructure(4, 4, 16);
	}

	@Test
	public void testByValue8AlignedStructure() throws Exception {
		checkByValueAlignedStructure(8, 8, 16);
	}

	@Test
	public void testByValue16AlignedStructure() throws Exception {
		checkByValueAlignedStructure(16, 16, 16);
	}

	public void checkByValueAlignedStructure(int value, int alignment, int length)
			throws Exception {
		emptyStructure.setInternallyAligned(true);
		emptyStructure.setMinimumAlignment(value);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyStructure.add(new ByteDataType());
		emptyStructure.add(new FloatDataType());
		emptyStructure.add(arrayDt);

		init(emptyStructure, pgmRootCat, false);
		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		JRadioButton byValueMinAlignButton =
			(JRadioButton) getInstanceField("byValueMinAlignButton", editorPanel);
		assertNotNull(byValueMinAlignButton);
		assertEquals(true, byValueMinAlignButton.isSelected());

		JTextField minAlignField =
			(JTextField) getInstanceField("minAlignValueTextField", editorPanel);
		assertNotNull(minAlignField);
		assertEquals("" + value, minAlignField.getText());

		assertEquals(false, structureModel.viewComposite.isDefaultAligned());
		assertEquals(false, structureModel.viewComposite.isMachineAligned());
		assertEquals(value, structureModel.getMinimumAlignment());

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 8, 5, "char[5]", arrayDt, "", "");
		assertLength(length);
		assertActualAlignment(alignment);
	}

	@Test
	public void testDefaultAlignedPacked1Structure() throws Exception {
		int value = 1;
		emptyStructure.setInternallyAligned(true);
		emptyStructure.setPackingValue(value);

		init(emptyStructure, pgmRootCat, false);
		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		JRadioButton byValuePackingButton =
			(JRadioButton) findComponentByName(editorPanel, "By Value Packing");
		assertNotNull(byValuePackingButton);
		JTextField packingValueField =
			(JTextField) findComponentByName(editorPanel, "Packing Value");
		assertNotNull(packingValueField);
		assertEquals(true, byValuePackingButton.isSelected());
		assertEquals("" + value, packingValueField.getText());

		assertEquals(true, structureModel.viewComposite.isDefaultAligned());
		assertEquals(false, structureModel.viewComposite.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, structureModel.getMinimumAlignment());

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, 5, "char[5]", arrayDt, "", "");
		assertLength(10);
		assertActualAlignment(1);
	}

	@Test
	public void testAlignedEditToFunctionDefinitionDataType() throws Exception {
		int value = 1;

		startTransaction("addExternal");
		ExternalLocation extLoc = program.getExternalManager().addExtFunction(Library.UNKNOWN,
			"extLabel", null, SourceType.USER_DEFINED);
		Function function = extLoc.createFunction();
		endTransaction(true);

		String name = function.getName();
		FunctionDefinitionDataType functionDefinitionDataType =
			new FunctionDefinitionDataType(function, true);
		FunctionDefinition functionDefinition = null;
		boolean commit = false;
		txId = program.startTransaction("Modify Program");
		try {
			simpleStructure.setInternallyAligned(true);
			simpleStructure.setPackingValue(value);

			programDTM = program.getListing().getDataTypeManager();
			functionDefinition =
				(FunctionDefinition) programDTM.resolve(functionDefinitionDataType, null);
			commit = true;
		}
		finally {
			program.endTransaction(txId, commit);
		}
		assertNotNull(functionDefinition);

		init(simpleStructure, pgmBbCat, false);

		int column = model.getDataTypeColumn();
		DataType dt = functionDefinition;

		assertEquals(28, model.getLength());
		assertEquals(-1, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		deleteAllInCellEditor();
		type(name);
		enter();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString(name + " *", 1, column);// Was function definition converted to a pointer?
		assertEquals(30, model.getLength());
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
	}

	@Test
	public void testSelectionOnGoFromUnalignedToAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		assertTrue(structureModel.hasChanges());// initial unsaved empty structure
		assertTrue(structureModel.isValidName());// name should be valid
		assertEquals(structureModel.getTypeName(), "Structure");
		assertEquals(emptyStructure.getName(), structureModel.getCompositeName());
		assertEquals(emptyStructure.getDescription(), structureModel.getDescription());
		assertEquals(pgmRootCat.getCategoryPathName(),
			structureModel.getOriginalCategoryPath().getPath());
		assertEquals(0, structureModel.getNumComponents());// no components
		assertEquals(1, structureModel.getRowCount());// blank row
		assertIsInternallyAligned(false);
		assertPackingValue(Composite.NOT_PACKING);
		assertMinimumAlignmentType(AlignmentType.DEFAULT_ALIGNED);
		assertMinimumAlignmentValue(Composite.DEFAULT_ALIGNMENT_VALUE);
		assertLength(0);
		assertActualAlignment(1);
		assertEquals(0, structureModel.getNumSelectedComponentRows());
		assertEquals(1, structureModel.getNumSelectedRows());
		checkSelection(new int[] { 0 });

		invoke(insertUndefinedAction);
		invoke(insertUndefinedAction);
		invoke(insertUndefinedAction);

		checkSelection(new int[] { 3 });

		pressButtonByName(editorPanel, "Internally Aligned");

		assertEquals(0, structureModel.getNumComponents());
		assertEquals(1, structureModel.getRowCount());
		assertLength(0);
		assertActualAlignment(1);
		checkSelection(new int[] { 0 });
	}

//	public void testTurnOffAlignmentInStructure() throws Exception {
//		emptyStructure.setInternallyAligned(true);
//		emptyStructure.setMinimumAlignment(8);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		JRadioButton byValueButton = (JRadioButton)findComponentByName(getPanel(), "By Value Minimum Alignment");
//		assertEquals(true, byValueButton.isSelected());
//		JTextField minAlignField = (JTextField)findComponentByName(getPanel(), "Minimum Alignment Value");
//		assertEquals("8", minAlignField.getText());
//		
//		assertEquals(false, structureModel.viewComposite.isDefaultAligned());
//		assertEquals(false, structureModel.viewComposite.isMachineAligned());
//		assertEquals(8, structureModel.getMinimumAlignment());
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(8);
//		assertActualAlignment(8);
//		assertEquals(true, structureModel.isAligned());
//		
//		pressButtonByName(getPanel(), "Internally Aligned");
//
//		assertEquals(false, structureModel.isAligned());
//		assertEquals(true, structureModel.viewComposite.isDefaultAligned());
//		assertEquals(false, structureModel.viewComposite.isMachineAligned());
//		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, structureModel.getMinimumAlignment());
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(5);
//		assertActualAlignment(1);
//	}
//	
//	public void testInsertUnaligned1() throws Exception {
//		emptyStructure.setInternallyAligned(false);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(5);
//		assertActualAlignment(1);
//		
//		DataType asciiDt = model.getOriginalDataTypeManager().findDataType("/char");
//		assertNotNull(asciiDt);
//		insertAtPoint(asciiDt,0,0);
//		
//		assertEquals(4, structureModel.getNumComponents());
//		assertEquals(5, structureModel.getRowCount());
//		checkRow(0, 1, "ch", asciiDt, "", "");
//		checkRow(1, 1, "db", new ByteDataType(), "", "");
//		checkRow(2, 4, "float", new FloatDataType(), "", "");
//		checkRow(3, 5, "char[5]", arrayDt, "", "");
//		assertLength(5);
//		assertActualAlignment(1);
//	}
//	
//	public void testInsertUnaligned2() throws Exception {
//		emptyStructure.setInternallyAligned(false);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(5);
//		assertActualAlignment(1);
//		
//		DataType asciiDt = model.getOriginalDataTypeManager().findDataType("/char");
//		assertNotNull(asciiDt);
//		insertAtPoint(asciiDt,2,3);
//		
//		assertEquals(4, structureModel.getNumComponents());
//		assertEquals(5, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 1, "ch", asciiDt, "", "");
//		checkRow(3, 5, "char[5]", arrayDt, "", "");
//		assertLength(5);
//		assertActualAlignment(1);
//	}
//	
//	public void testInsertUnaligned3() throws Exception {
//		emptyStructure.setInternallyAligned(false);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(5);
//		assertActualAlignment(1);
//		
//		DataType doubleDt = model.getOriginalDataTypeManager().findDataType("/double");
//		assertNotNull(doubleDt);
//		insertAtPoint(doubleDt,3,3);
//		
//		assertEquals(4, structureModel.getNumComponents());
//		assertEquals(5, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		checkRow(3, 8, "double", doubleDt, "", "");
//		assertLength(8);
//		assertActualAlignment(1);
//	}
//	
//	public void testReplaceUnaligned1() throws Exception {
//		emptyStructure.setInternallyAligned(false);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(5);
//		assertActualAlignment(1);
//		
//		DataType asciiDt = model.getOriginalDataTypeManager().findDataType("/char");
//		assertNotNull(asciiDt);
//		addAtPoint(asciiDt,2,3);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 1, "ch", asciiDt, "", "");
//		assertLength(4);
//		assertActualAlignment(1);
//	}
//	
//	public void testReplaceUnaligned2() throws Exception {
//		emptyStructure.setInternallyAligned(false);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(5);
//		assertActualAlignment(1);
//		
//		DataType doubleDt = model.getOriginalDataTypeManager().findDataType("/double");
//		assertNotNull(doubleDt);
//		addAtPoint(doubleDt,3,3);
//		
//		assertEquals(4, structureModel.getNumComponents());
//		assertEquals(5, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		checkRow(3, 8, "double", doubleDt, "", "");
//		assertLength(8);
//		assertActualAlignment(1);
//	}
//	
//	public void testInsertAligned1() throws Exception {
//		emptyStructure.setInternallyAligned(true);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(8);
//		assertActualAlignment(4);
//		
//		DataType asciiDt = model.getOriginalDataTypeManager().findDataType("/char");
//		assertNotNull(asciiDt);
//		insertAtPoint(asciiDt,0,0);
//		
//		assertEquals(4, structureModel.getNumComponents());
//		assertEquals(5, structureModel.getRowCount());
//		checkRow(0, 1, "ch", asciiDt, "", "");
//		checkRow(1, 1, "db", new ByteDataType(), "", "");
//		checkRow(2, 4, "float", new FloatDataType(), "", "");
//		checkRow(3, 5, "char[5]", arrayDt, "", "");
//		assertLength(8);
//		assertActualAlignment(4);
//	}
//	
//	public void testInsertAligned2() throws Exception {
//		emptyStructure.setInternallyAligned(true);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(8);
//		assertActualAlignment(4);
//		
//		DataType asciiDt = model.getOriginalDataTypeManager().findDataType("/char");
//		assertNotNull(asciiDt);
//		insertAtPoint(asciiDt,2,3);
//		
//		assertEquals(4, structureModel.getNumComponents());
//		assertEquals(5, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 1, "ch", asciiDt, "", "");
//		checkRow(3, 5, "char[5]", arrayDt, "", "");
//		assertLength(8);
//		assertActualAlignment(4);
//	}
//	
//	public void testInsertAligned3() throws Exception {
//		emptyStructure.setInternallyAligned(true);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(8);
//		assertActualAlignment(4);
//		
//		DataType doubleDt = model.getOriginalDataTypeManager().findDataType("/double");
//		assertNotNull(doubleDt);
//		insertAtPoint(doubleDt,3,3);
//		
//		assertEquals(4, structureModel.getNumComponents());
//		assertEquals(5, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		checkRow(3, 8, "double", doubleDt, "", "");
//		assertLength(8);
//		assertActualAlignment(8);
//	}
//	
//	public void testReplaceAligned1() throws Exception {
//		emptyStructure.setInternallyAligned(true);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(8);
//		assertActualAlignment(4);
//		
//		DataType asciiDt = model.getOriginalDataTypeManager().findDataType("/char");
//		assertNotNull(asciiDt);
//		addAtPoint(asciiDt,2,3);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 1, "ch", asciiDt, "", "");
//		assertLength(4);
//		assertActualAlignment(4);
//	}
//	
//	public void testReplaceAligned2() throws Exception {
//		emptyStructure.setInternallyAligned(true);
//		
//		DataType arrayDt = new ArrayDataType(new AsciiDataType(), 5, 1);
//		emptyStructure.add(new ByteDataType());
//		emptyStructure.add(new FloatDataType());
//		emptyStructure.add(arrayDt);
//		
//		init(emptyStructure, pgmRootCat, false);
//		
//		assertEquals(3, structureModel.getNumComponents());
//		assertEquals(4, structureModel.getRowCount());
//		checkRow(0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, "char[5]", arrayDt, "", "");
//		assertLength(8);
//		assertActualAlignment(4);
//		
//		DataType doubleDt = model.getOriginalDataTypeManager().findDataType("/double");
//		assertNotNull(doubleDt);
//		addAtPoint(doubleDt,3,3);
//		
//		assertEquals(4, structureModel.getNumComponents());
//		assertEquals(5, structureModel.getRowCount());
//		checkRow(0, 0, 1, "db", new ByteDataType(), "", "");
//		checkRow(1, 1, 4, "float", new FloatDataType(), "", "");
//		checkRow(2, 5, 5, "char[5]", arrayDt, "", "");
//		checkRow(3, 10, 8, "double", doubleDt, "", "");
//		assertLength(18);
//		assertActualAlignment(8);
//	}

	////////////////////////////

	private void checkRow(int rowIndex, int offset, int length, String mnemonic, DataType dataType,
			String name, String comment) {
		assertTrue(dataType.isEquivalent(structureModel.getComponent(rowIndex).getDataType()));
		assertEquals("" + offset,
			structureModel.getValueAt(rowIndex, structureModel.getOffsetColumn()));
		assertEquals("" + length,
			structureModel.getValueAt(rowIndex, structureModel.getLengthColumn()));
		assertEquals(mnemonic,
			structureModel.getValueAt(rowIndex, structureModel.getMnemonicColumn()));
		assertEquals(name, structureModel.getValueAt(rowIndex, structureModel.getNameColumn()));
		assertEquals(comment,
			structureModel.getValueAt(rowIndex, structureModel.getCommentColumn()));
	}

	private DataTypeComponent addDataType(DataType dataType) {
		return structureModel.viewComposite.add(dataType);
	}

}
