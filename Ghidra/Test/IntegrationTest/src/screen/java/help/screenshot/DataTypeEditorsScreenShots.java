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
package help.screenshot;

import java.awt.Component;
import java.awt.Window;
import java.util.*;

import javax.swing.*;

import org.junit.Test;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.tree.GTree;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.plugin.core.compositeeditor.*;
import ghidra.app.plugin.core.datamgr.editor.EnumEditorProvider;
import ghidra.app.plugin.core.datamgr.util.DataTypeChooserDialog;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;

public class DataTypeEditorsScreenShots extends GhidraScreenShotGenerator {

	public DataTypeEditorsScreenShots() {
		super();
	}

	@Test
	public void testDialog() {

		positionListingTop(0x40D3B8);
		performAction("Choose Data Type", "DataPlugin", false);
		captureDialog();
	}

	@Test
	public void testDialog_Multiple_Match() throws Exception {

		positionListingTop(0x40D3B8);
		DropDownSelectionTextField<?> textField = showTypeChooserDialog();

		triggerText(textField, "undefined");

		DialogComponentProvider dialog = getDialog();
		JComponent component = dialog.getComponent();
		Window dataTypeDialog = windowForComponent(component);
		Window[] popUpWindows = dataTypeDialog.getOwnedWindows();

		List<Component> dataTypeWindows = new ArrayList<>(Arrays.asList(popUpWindows));
		dataTypeWindows.add(dataTypeDialog);

		captureComponents(dataTypeWindows);
		closeAllWindowsAndFrames();
	}

	private DropDownSelectionTextField<?> showTypeChooserDialog() throws Exception {

		// type something to trigger indexing so that we avoid the modal dialog, which steals focus
		// and then, when done, triggers the text field to select all its text
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		service.getSortedDataTypeList();

		performAction("Choose Data Type", "DataPlugin", false);

		DropDownSelectionTextField<?> textField =
			findComponent(getDialog(), DropDownSelectionTextField.class);

		return textField;
	}

	@Test
	public void testDialog_Single_Match() throws Exception {

		positionListingTop(0x40D3B8);
		DropDownSelectionTextField<?> textField = showTypeChooserDialog();
		triggerText(textField, "qword");

		DialogComponentProvider dialog = getDialog();
		JComponent component = dialog.getComponent();
		Window dataTypeDialog = windowForComponent(component);
		Window[] popUpWindows = dataTypeDialog.getOwnedWindows();

		List<Component> dataTypeWindows = new ArrayList<>(Arrays.asList(popUpWindows));
		dataTypeWindows.add(dataTypeDialog);

		captureComponents(dataTypeWindows);

	}

	@Test
	public void testDialog_Create_Pointer() throws Exception {

		positionListingTop(0x40D3B8);
		DropDownSelectionTextField<?> textField = showTypeChooserDialog();
		setText(textField, "word*");

		captureDialog();
	}

	@Test
	public void testDialog_Select_Tree() {

		positionListingTop(0x40D3B8);
		performAction("Choose Data Type", "DataPlugin", false);

		DialogComponentProvider dialog = getDialog();
		final JButton browseButton = findButtonByIcon(dialog, ButtonPanelFactory.BROWSE_ICON);
		pressButton(browseButton, false);
		waitForSwing();

		dialog = getDialog(DataTypeChooserDialog.class);
		GTree tree = (GTree) getInstanceField("tree", dialog);
		selectPath(tree, "Data Types", "BuiltInTypes", "char");

		captureDialog(DataTypeChooserDialog.class, 408, 324);
	}

	@Test
	public void testBytesNumberInputDialog() {

		createDetailedStructure(0x40d2b8, false);

		goToListing(0x40d2b8, true);
		performAction("Edit Data Type", "DataPlugin", true);

		ComponentProvider structureEditor = getProvider(StructureEditorProvider.class);

		// get structure table and select a row
		CompositeEditorPanel editorPanel =
			(CompositeEditorPanel) getInstanceField("editorPanel", structureEditor);
		JTable table = editorPanel.getTable();
		int numRows = table.getRowCount();
		selectRow(table, numRows - 2);

		performAction("Cycle: char,string,unicode", "DataTypeManagerPlugin", structureEditor, true);
		performAction("Cycle: char,string,unicode", "DataTypeManagerPlugin", structureEditor,
			false);
		waitForSwing();

		captureDialog();
	}

	@Test
	public void testEnumEditor() {

		createEnum(0x40d2b8);

		goToListing(0x40d2b8, true);
		performAction("Edit Data Type", "DataPlugin", true);

		captureIsolatedProvider(EnumEditorProvider.class, 600, 300);
	}

	@Test
	public void testNumDuplicates() {

		createDetailedStructure(0x40d2b8, false);

		goToListing(0x40d2b8, true);
		performAction("Edit Data Type", "DataPlugin", true);

		ComponentProvider structureEditor = getProvider(StructureEditorProvider.class);

		// get structure table and select a row
		CompositeEditorPanel editorPanel =
			(CompositeEditorPanel) getInstanceField("editorPanel", structureEditor);
		JTable table = editorPanel.getTable();
		int numRows = table.getRowCount();
		selectRow(table, numRows - 2);

		performAction("Editor: Duplicate Multiple of Component", "DataTypeManagerPlugin",
			structureEditor, false);
		waitForSwing();

		captureDialog();
		closeAllWindowsAndFrames();
	}

	@Test
	public void testNumElementsPrompt() {

		createDetailedStructure(0x40d2b8, false);

		goToListing(0x40d2b8, true);
		performAction("Edit Data Type", "DataPlugin", true);

		ComponentProvider structureEditor = getProvider(StructureEditorProvider.class);

		// get structure table and select a row
		CompositeEditorPanel editorPanel =
			(CompositeEditorPanel) getInstanceField("editorPanel", structureEditor);
		JTable table = editorPanel.getTable();
		int numRows = table.getRowCount();
		selectRow(table, numRows - 2);

		performAction("Editor: Create Array", "DataTypeManagerPlugin", structureEditor, false);
		waitForSwing();

		captureDialog();
	}

	@Test
	public void testStructureEditor() {

		createDetailedStructure(0x40d2b8, false);

		goToListing(0x40d2b8, true);
		performAction("Edit Data Type", "DataPlugin", true);

		captureProvider(StructureEditorProvider.class);
	}

	@Test
	public void testStructureEditorPacked() {

		createDetailedStructure(0x40d2b8, true, false);

		goToListing(0x40d2b8, true);

		performAction("Edit Data Type", "DataPlugin", true);

		captureProvider(StructureEditorProvider.class);
	}

	@Test
	public void testStructureEditorWithFlexArray() {

		createDetailedStructure(0x40d2b8, true, true);

		goToListing(0x40d2b8, true);

		performAction("Edit Data Type", "DataPlugin", true);

		captureProvider(StructureEditorProvider.class);
	}

	@Test
	public void testStructureEditBitfield() {

		createDetailedStructure(0x40d2b8, false, true);

		goToListing(0x40d2b8, true);

		performAction("Edit Data Type", "DataPlugin", true);

		ComponentProvider structureEditor = getProvider(StructureEditorProvider.class);

		// get structure table and select a row
		CompositeEditorPanel editorPanel =
			(CompositeEditorPanel) getInstanceField("editorPanel", structureEditor);
		JTable table = editorPanel.getTable();
		selectRow(table, 4); // select byte:3 bitfield

		performAction("Editor: Edit Bitfield", "DataTypeManagerPlugin", structureEditor, false);
		waitForSwing();

		captureDialog();
	}

	@Test
	public void testUnionEditor() {

		createUnion(0x40d2b8);

		goToListing(0x40d2b8, true);
		performAction("Edit Data Type", "DataPlugin", true);

		captureIsolatedProvider(UnionEditorProvider.class, 700, 425);
	}

	@Test
	public void testUnionEditorPacked() {

		createPackedUnion(0x40d2b8);

		goToListing(0x40d2b8, true);
		performAction("Edit Data Type", "DataPlugin", true);

		captureIsolatedProvider(UnionEditorProvider.class, 700, 425);
	}

	private void createDetailedStructure(long address, boolean includeFlexArray) {

		goToListing(address);

		StructureDataType struct = new StructureDataType("MyNonPackedStruct", 0);
		struct.add(new ByteDataType(), "myByteElement", "non-packed byte");
		struct.add(new ByteDataType(), "", "undefined element");
		struct.add(new WordDataType(), "myWordElement", "non-packed word");
		struct.add(new ByteDataType(), "myByteElement2", "another non-packed byte");
		struct.add(new DWordDataType(), "myDWordElement", "non-packed dword");
		if (includeFlexArray) {
			struct.setFlexibleArrayComponent(CharDataType.dataType, "flex",
				"unsized flexible array");
		}
		struct.clearComponent(1);
		struct.setDescription("This is an example of an non-packed structure " +
			(includeFlexArray ? "with a flexible char array" : "of size 9") + ".");

		CreateDataCmd createDataCmd = new CreateDataCmd(addr(address), struct);
		tool.execute(createDataCmd, program);
		waitForBusyTool(tool);
	}

	private void createDetailedStructure(long address, boolean packed,
			boolean includeBitFieldsAndFlexArray) {

		goToListing(address);

		StructureDataType struct = new StructureDataType("MyPackedStruct", 0);
		struct.setPackingEnabled(true); // allow proper default packing
		struct.add(new ByteDataType(), "myByteElement", "alignment 1");
		struct.add(new ByteDataType(), "", "This is my undefined element");
		struct.add(new WordDataType(), "myWordElement", "alignment 2");
		if (includeBitFieldsAndFlexArray) {
			try {
				struct.addBitField(ByteDataType.dataType, 1, "myBitField1", "alignment 1");
				struct.addBitField(ByteDataType.dataType, 2, "myBitField2", "alignment 1");
				struct.addBitField(ByteDataType.dataType, 3, "myBitField3", "alignment 1");
			}
			catch (InvalidDataTypeException e) {
				failWithException("Unexpected Error", e);
			}
		}
		struct.add(new ByteDataType(), "myByteElement2", "alignment 1");
		struct.add(new DWordDataType(), "myDWordElement", "alignment 4");
		if (includeBitFieldsAndFlexArray) {
			struct.setFlexibleArrayComponent(CharDataType.dataType, "flex",
				"unsized flexible array");
		}
		struct.clearComponent(1);
		struct.setDescription("Members packed " +
			(includeBitFieldsAndFlexArray ? "with bitfields and a flexible char array"
					: "according to their alignment size") +
			". ");
		struct.setPackingEnabled(packed);

		CreateDataCmd createDataCmd = new CreateDataCmd(addr(address), struct);
		tool.execute(createDataCmd, program);
		waitForBusyTool(tool);
	}

	private void createUnion(long address) {

		goToListing(address);

		UnionDataType union = new UnionDataType("MyUnion");
		union.add(new ByteDataType(), "myByteElement", "non-packed byte");
		union.add(new WordDataType(), "myWordElement", "non-packed word");
		union.add(new DWordDataType(), "myDWordElement", "non-packed dword");
		union.add(new QWordDataType(), "myQWordElement", "non-packed qword");
		union.setDescription("This is an example of an non-packed union.");

		CreateDataCmd createDataCmd = new CreateDataCmd(addr(address), union);
		tool.execute(createDataCmd, program);
		waitForBusyTool(tool);
	}

	private void createPackedUnion(long address) {

		goToListing(address);

		UnionDataType union = new UnionDataType("MyUnion");
		union.add(new ByteDataType(), "myByteElement", "packed byte");
		union.add(new WordDataType(), "myWordElement", "packed word");
		union.add(new DWordDataType(), "myDWordElement", "packed dword");
		union.add(new QWordDataType(), "myQWordElement", "packed qword");
		union.setDescription("This is an example of an packed union.");
		union.setPackingEnabled(true);

		CreateDataCmd createDataCmd = new CreateDataCmd(addr(address), union);
		tool.execute(createDataCmd, program);
		waitForBusyTool(tool);
	}

	private void createEnum(long address) {

		goToListing(address);

		EnumDataType myEnum = new EnumDataType("ExpressionType", 1);
		myEnum.add("TYPE_INT", 1);
		myEnum.add("TYPE_FLOAT", 2);
		myEnum.add("TYPE_STRING", 3);
		myEnum.add("TYPE_UNKNOWN", 4);
		myEnum.setDescription("Enumerated data type.");

		CreateDataCmd createDataCmd = new CreateDataCmd(addr(address), myEnum);
		tool.execute(createDataCmd, program);
		waitForBusyTool(tool);
	}
}
