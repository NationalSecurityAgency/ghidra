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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.plugin.core.data.EditDataFieldDialog;
import ghidra.program.model.data.*;

public class DecompilerEditDataFieldTest extends AbstractDecompilerTest {

	private static final long INIT_STRING_ADDR = 0X080483c7;

	private DockingActionIf editFieldAction;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		editFieldAction = getAction(decompiler, "Quick Edit Field");
	}

	@Override
	protected String getProgramName() {
		return "elf/CentOS/32bit/decomp.gzf";
	}

	@Test
	public void testActionEnablement() throws Exception {

		/*
		
		 Decomp of 'init_string':
		
		 	1|
			2| void init_string(mystring *ptr)
			3|
			4| {
			5|   ptr->alloc = 0;
			6|   return;
			7| }
			8|
		
		 */

		decompile(INIT_STRING_ADDR);

		//
		// Action should not enabled unless on the data type
		//
		// Empty line
		int line = 1;
		int charPosition = 0;
		setDecompilerLocation(line, charPosition);
		assertActionNotInPopup();

		// Signature - first param; a data type
		line = 2;
		charPosition = 17;
		setDecompilerLocation(line, charPosition);
		assertActionNotInPopup();

		// Signature - first param name
		line = 2;
		charPosition = 26;
		setDecompilerLocation(line, charPosition);
		assertActionNotInPopup();

		// Syntax - {
		line = 4;
		charPosition = 0;
		setDecompilerLocation(line, charPosition);
		assertActionNotInPopup();

		// Data access - the data type itself
		line = 5;
		charPosition = 2;
		setDecompilerLocation(line, charPosition);
		assertActionNotInPopup();

		// Data access - the data type field dereference
		line = 5;
		charPosition = 7;
		setDecompilerLocation(line, charPosition);
		assertActionInPopup();
	}

	@Test
	public void testEditName() {

		/*
		
		 Decomp of 'init_string':
		
		 	1|
			2| void init_string(mystring *ptr)
			3|
			4| {
			5|   ptr->alloc = 0;
			6|   return;
			7| }
			8|
		
		 */

		decompile(INIT_STRING_ADDR);

		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
		Structure structure = (Structure) dtm.getDataType(new DataTypePath("/", "mystring"));

		// Data access - the data type field dereference
		int line = 5;
		int charPosition = 7;
		setDecompilerLocation(line, charPosition);
		assertToken("alloc", line, charPosition);
		EditDataFieldDialog dialog = performEditField();

		assertEquals("alloc", structure.getComponent(0).getFieldName());
		assertEquals("alloc", getNameText(dialog));

		setNameText(dialog, "weight");

		pressOk(dialog);
		waitForDecompiler();

		setDecompilerLocation(line, charPosition);
		assertToken("weight", line, charPosition);
		assertEquals("weight", structure.getComponent(0).getFieldName());
	}

	@Test
	public void testEditDataType() {

		/*
		
		 Decomp of 'init_string':
		
		 	1|
			2| void init_string(mystring *ptr)
			3|
			4| {
			5|   ptr->alloc = 0;
			6|   return;
			7| }
			8|
		
		 */

		decompile(INIT_STRING_ADDR);

		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
		Structure structure = (Structure) dtm.getDataType(new DataTypePath("/", "mystring"));

		// Data access - the data type field dereference
		int line = 5;
		int charPosition = 7;
		setDecompilerLocation(line, charPosition);
		assertToken("alloc", line, charPosition);
		EditDataFieldDialog dialog = performEditField();

		assertEquals("int", structure.getComponent(0).getDataType().getDisplayName());
		assertEquals("int", getDataTypeText(dialog));

		setDataType(dialog, new DWordDataType());

		pressOk(dialog);
		waitForDecompiler();

		setDecompilerLocation(line, charPosition);
		assertToken("alloc", line, charPosition);
		assertEquals("dword", structure.getComponent(0).getDataType().getDisplayName());
	}

	@Test
	public void testEditComment() {

		/*
		
		 Decomp of 'init_string':
		
		 	1|
			2| void init_string(mystring *ptr)
			3|
			4| {
			5|   ptr->alloc = 0;
			6|   return;
			7| }
			8|
		
		 */

		decompile(INIT_STRING_ADDR);

		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
		Structure structure = (Structure) dtm.getDataType(new DataTypePath("/", "mystring"));

		// Data access - the data type field dereference
		int line = 5;
		int charPosition = 7;
		setDecompilerLocation(line, charPosition);
		assertToken("alloc", line, charPosition);
		EditDataFieldDialog dialog = performEditField();

		assertEquals(null, structure.getComponent(0).getComment());
		assertEquals("", getCommentText(dialog));

		setCommentText(dialog, "comment");

		pressOk(dialog);
		waitForDecompiler();

		setDecompilerLocation(line, charPosition);
		assertToken("alloc", line, charPosition);
		assertEquals("comment", structure.getComponent(0).getComment());
	}

//=================================================================================================
// Private Methods
//=================================================================================================	

	private EditDataFieldDialog performEditField() {

		DecompilerActionContext context =
			new DecompilerActionContext(provider, addr(0x0), false);
		performAction(editFieldAction, context, false);

		return waitForDialogComponent(EditDataFieldDialog.class);
	}

	private void pressOk(EditDataFieldDialog dialog) {
		pressButtonByText(dialog, "OK");
	}

	private String getNameText(EditDataFieldDialog dialog) {
		return runSwing(() -> dialog.getNameText());
	}

	private void setNameText(EditDataFieldDialog dialog, String newName) {
		runSwing(() -> dialog.setNameText(newName));
	}

	private String getCommentText(EditDataFieldDialog dialog) {
		return runSwing(() -> dialog.getCommentText());
	}

	private void setCommentText(EditDataFieldDialog dialog, String newName) {
		runSwing(() -> dialog.setCommentText(newName));
	}

	private String getDataTypeText(EditDataFieldDialog dialog) {
		return runSwing(() -> dialog.getDataTypeText());
	}

	private void setDataType(EditDataFieldDialog dialog, DataType dataType) {
		runSwing(() -> dialog.setDataType(dataType));
	}

	private void assertActionInPopup() {
		ActionContext context = provider.getActionContext(null);
		assertTrue("'Edit Field' action should be enabled; currently selected token: " +
			provider.currentTokenToString(), editFieldAction.isAddToPopup(context));
	}

	private void assertActionNotInPopup() {
		ActionContext context = provider.getActionContext(null);
		assertFalse(
			"'Edit Field' action should not be enabled; currently selected token: " +
				provider.currentTokenToString(),
			editFieldAction.isAddToPopup(context));
	}

}
