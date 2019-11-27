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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Set;

import org.junit.Test;

import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.program.model.listing.CodeUnit;

public class DecompilerClangTest extends AbstractDecompilerTest {

	@Override
	protected String getProgramName() {
		return "ghidra/app/extension/datatype/finder/functions_with_structure_usage.gzf";
	}

	@Test
	public void testClangTextField_getTokenIndex() {

		decompile("100000bf0"); // 'main'

		/*
		 	24: return 0;
		 */
		int line = 24;
		assertToken("return", line, 0, 1, 2, 3, 4, 5);
		assertTokenIndex(0, line, 0, 1, 2, 3, 4, 5);
		assertToken(" ", line, 6);
		assertTokenIndex(1, line, 6);
		assertToken("0", line, 7);
		assertTokenIndex(2, line, 7);
		assertToken(";", line, 8);
		assertTokenIndex(3, line, 8);
	}

	@Test
	public void testClangTextField_getNextTokenIndex() {

		decompile("100000bf0"); // 'main'

		/*
		 	24: return 0;
		 */
		int line = 24;
		int nextIndex = 1;
		assertToken("return", line, 1, 2, 3, 4, 5);
		assertNextTokenIndex(nextIndex, line, 1, 2, 3, 4, 5);
		assertToken(" ", line, 6);
		assertNextTokenIndex(nextIndex, line, 6); // same index when at the start of the next token
		assertToken("0", line, 7);
		assertNextTokenIndex(++nextIndex, line, 7);
		assertToken(";", line, 8);
		assertNextTokenIndex(++nextIndex, line, 8);
	}

	@Test
	public void testCommentAnnotation() {

		String commentAddress = "100000d80";
		String linkDisplayText = "function _call_structure_A()";
		String linkAddress = "100000e10";
		String annotation = "{@addr " + linkAddress + " \"" + linkDisplayText + "\"}";
		setComment(commentAddress, CodeUnit.PRE_COMMENT, "This is calling " + annotation + ".");

		decompile("100000d60"); // _call_structure_A()

		int line = 5;  // the entire line is a comment token
		String displayText = "/* This is calling " + linkDisplayText + ". */";
		assertDisplayText(displayText, line);

		int linkPosition = displayText.indexOf(linkDisplayText); // the clickable part of the comment
		setDecompilerLocation(line, linkPosition);
		doubleClick();

		assertCurrentAddress(addr(linkAddress));
	}

	@Test
	public void testNewDecompileNavigatesToFunctionSignature() {

		decompile("100000bf0"); // 'main'
		int line = 5; // arbitrary value in view
		int charPosition = 5; // arbitrary
		setDecompilerLocation(line, charPosition);

		decompile("100000d60"); // _call_structure_A()
		line = 0; // function signature
		charPosition = 0; // start of signature
		assertCurrentLocation(line, charPosition);
	}

	@Test
	public void testDecompiler_CopyFromSymbolWithoutSelection() throws Exception {

		/*
		 	
		 Decomp of '_call_structure_A':
		 
			1|
			2| void _call_structure_A(A *a)
			3|
			4| {
			5|  	_printf("call_structure_A: %s\n",a->name);
			6|  	_printf("call_structure_A: %s\n",(a->b).name);
			7|  	_printf("call_structure_A: %s\n",(a->b).c.name);
			8|  	_printf("call_structure_A: %s\n",(a->b).c.d.name);
			9|  	_printf("call_structure_A: %s\n",(a->b).c.d.e.name);
		   10|  	_call_structure_B(&a->b);
		   11|  	return;
		   12|	}
		
		 */

		decompile("100000d60"); // '_call_structure_A'
		int line = 2; 		  // void
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		copy();
		String copiedText = getClipboardText();
		assertEquals("void", copiedText);

		line = 5; 			// _printf
		charPosition = 2; 	// 
		setDecompilerLocation(line, charPosition);

		copy();
		copiedText = getClipboardText();
		assertEquals("_printf", copiedText);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void copy() {

		Set<DockingActionIf> actions = getActionsByOwnerAndName(tool, "ClipboardPlugin", "Copy");
		for (DockingActionIf action : actions) {
			Object service = getInstanceField("clipboardService", action);
			if (service.getClass().toString().contains("Decomp")) {
				performAction(action);
				return;
			}
		}

		fail("Could not find Decompiler Copy action");
	}

	private void setComment(String address, int type, String comment) {
		applyCmd(program, new SetCommentCmd(addr(address), type, comment));
	}

	private void assertNextTokenIndex(int expectedIndex, int line, int... cols) {
		for (int col : cols) {
			FieldLocation loc = loc(line, col);
			int actualIndex = getNextTokenIndex(getTextField(loc), loc);
			assertEquals(expectedIndex, actualIndex);
		}
	}

	private void assertTokenIndex(int expectedIndex, int line, int... cols) {
		for (int col : cols) {
			FieldLocation loc = loc(line, col);
			int actualIndex = getTokenIndex(getTextField(loc), loc);
			assertEquals(expectedIndex, actualIndex);
		}
	}

	private ClangTextField getTextField(FieldLocation loc) {
		ClangTextField field = getFieldForLine(loc.getIndex().intValue());
		return field;
	}

	private void assertDisplayText(String expected, int line) {
		FieldLocation loc = loc(line, 0 /*column*/);
		ClangTextField field = getFieldForLine(loc.getIndex().intValue());
		String actual = field.getText();
		assertEquals("Line text not as expected at line " + line, expected, actual);
	}

	private void assertCurrentLocation(int line, int col) {
		int oneBasedLine = line + 1;
		DecompilerPanel panel = provider.getDecompilerPanel();
		FieldLocation actual = panel.getCursorPosition();
		FieldLocation expected = loc(oneBasedLine, col);
		assertEquals("Decompiler cursor is not at the expected location", expected, actual);
	}

	private int getTokenIndex(ClangTextField field, FieldLocation loc) {
		Integer index = (Integer) invokeInstanceMethod("getTokenIndex", field,
			new Class[] { FieldLocation.class }, new Object[] { loc });
		return index;
	}

	private int getNextTokenIndex(ClangTextField field, FieldLocation loc) {
		Integer index = (Integer) invokeInstanceMethod("getNextTokenIndexStartingAfter", field,
			new Class[] { FieldLocation.class }, new Object[] { loc });
		return index;
	}

}
