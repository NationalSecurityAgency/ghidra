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

import java.awt.Color;
import java.awt.Window;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.swing.JButton;

import org.junit.Before;
import org.junit.Test;

import docking.action.DockingActionIf;
import docking.options.editor.GhidraColorChooser;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompileOptions.NamespaceStrategy;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.decompile.actions.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.CodeUnit;

public class DecompilerClangTest extends AbstractDecompilerTest {

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();
		OptionsService service = provider.getTool().getService(OptionsService.class);
		ToolOptions opt = service.getOptions("Decompiler");
		opt.setEnum("Display.Display Namespaces", NamespaceStrategy.Never);
	}

	@Override
	protected String getProgramName() {
		return "ghidra/app/extension/datatype/finder/functions_with_structure_usage.gzf";
	}

	@Test
	public void testClangTextField_getTokenIndex() {

		/*
			 1|	
			 2|	int _main(int argc,char **argv)
			 3|
			 4|	{
			 5|	  _a.id = 1;
			 6|	  _a.name = "A";
			 7|	  _b.id = 2;
			 8|	  _b.name = "B";
			 9|	  _c.id = 3;
			10|	  _c.name = "C";
			11|	  _d.id = 4;
			12|	  _d.name = "D";
			13|	  _e.id = 5;
			14|	  _e.name = "E";
			15|	  _c.d.e._0_8_ = CONCAT44(_e._4_4_,5);
			16|	  _d.e.name = "E";
			17|	  _c.d._0_8_ = CONCAT44(_d._4_4_,4);
			18|	  _c.d.name = "D";
			19|	  _c.d.e.name = "E";
			20|	  _d.e._0_8_ = _c.d.e._0_8_;
			21|	  _memcpy(&_b.c,&_c,0x30);
			22|	  _memcpy(&_a.b,&_b,0x40);
			23|	  _call_structure_A(&_a);
			24|	  return 0;
			25|	}
			16|
		 	
		 */

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

		/*
			 1|	
			 2|	int _main(int argc,char **argv)
			 3|
			 4|	{
			 5|	  _a.id = 1;
			 6|	  _a.name = "A";
			 7|	  _b.id = 2;
			 8|	  _b.name = "B";
			 9|	  _c.id = 3;
			10|	  _c.name = "C";
			11|	  _d.id = 4;
			12|	  _d.name = "D";
			13|	  _e.id = 5;
			14|	  _e.name = "E";
			15|	  _c.d.e._0_8_ = CONCAT44(_e._4_4_,5);
			16|	  _d.e.name = "E";
			17|	  _c.d._0_8_ = CONCAT44(_d._4_4_,4);
			18|	  _c.d.name = "D";
			19|	  _c.d.e.name = "E";
			20|	  _d.e._0_8_ = _c.d.e._0_8_;
			21|	  _memcpy(&_b.c,&_c,0x30);
			22|	  _memcpy(&_a.b,&_b,0x40);
			23|	  _call_structure_A(&_a);
			24|	  return 0;
			25|	}
			16|
		 	
		 */

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
		line = 2; // function signature
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
		charPosition = 2;
		setDecompilerLocation(line, charPosition);

		copy();
		copiedText = getClipboardText();
		assertEquals("_printf", copiedText);
	}

	@Test
	public void testPrimaryHighlighting_ParenthesesContents() {

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

		// 5:7 "_printf | ("..."
		int line = 5;
		int charPosition = 7;
		setDecompilerLocation(line, charPosition);

		assertPrimaryHighlights("(\"call_structure_A: %s\\n\",a->name)");
	}

	@Test
	public void testSecondaryHighlighting() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		ClangToken token1 = getToken();
		String text1 = token1.getText();
		assertEquals("_printf", text1);

		Color color = highlight();
		assertAllFieldsSecondaryHighlighted(token1, color);

		// 5:30 "a->name"
		line = 5;
		charPosition = 38;
		setDecompilerLocation(line, charPosition);
		ClangToken token2 = getToken();
		String text2 = token2.getText();
		assertEquals("name", text2);

		Color color2 = highlight();
		assertAllFieldsHighlighted(text1, color);
		assertAllFieldsSecondaryHighlighted(token2, color2);

		// 2:1 "void"
		line = 2;
		charPosition = 1;
		setDecompilerLocation(line, charPosition);
		ClangToken token3 = getToken();
		String text3 = token3.getText();
		assertEquals("void", text3);

		Color color3 = highlight();
		assertAllFieldsHighlighted(text1, color);
		assertAllFieldsHighlighted(text2, color2);
		assertAllFieldsSecondaryHighlighted(token3, color3);
	}

	@Test
	public void testSecondaryHighlighting_ClearHighlight_WithMultipleHighlights() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		ClangToken token = getToken();
		String text = token.getText();
		assertEquals("_printf", text);

		highlight();

		// 5:30 "a->name"
		line = 5;
		charPosition = 38;
		setDecompilerLocation(line, charPosition);
		ClangToken token2 = getToken();
		String text2 = token2.getText();
		assertEquals("name", text2);

		Color color2 = highlight();

		// 5:2 "_printf"
		line = 5;
		charPosition = 2;
		setDecompilerLocation(line, charPosition);
		removeSecondaryHighlight();

		assertNoFieldsSecondaryHighlighted(text);
		assertAllFieldsHighlighted(text2, color2);
	}

	@Test
	public void testSecondaryHighlighting_ClearAll() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		ClangToken token = getToken();
		String text = token.getText();
		assertEquals("_printf", text);

		highlight();

		// 5:30 "a->name"
		line = 5;
		charPosition = 38;
		setDecompilerLocation(line, charPosition);
		ClangToken token2 = getToken();
		String text2 = token2.getText();
		assertEquals("name", text2);

		highlight();

		clearAllHighlights();

		assertNoFieldsSecondaryHighlighted(text);
		assertNoFieldsSecondaryHighlighted(text2);
	}

	@Test
	public void testSecondaryHighlighting_RenameHighlightedVariable() {

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

		// 2:26 "a"
		int line = 2;
		int charPosition = 26;
		setDecompilerLocation(line, charPosition);

		ClangToken token = getToken();
		String text = token.getText();
		assertEquals("a", text);

		Color color = highlight();

		rename("bob");

		token = getToken();
		text = token.getText();
		assertEquals("bob", text);
		assertAllFieldsSecondaryHighlighted(token, color);
	}

	@Test
	public void testSecondaryHighlighting_HighlightColorGetsReused() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		ClangToken token = getToken();
		String text = token.getText();
		assertEquals("_printf", text);

		Color color = highlight();

		removeSecondaryHighlight();

		assertNoFieldsSecondaryHighlighted(text);

		Color secondColor = highlight();
		assertEquals(color, secondColor);
	}

	@Test
	public void testSecondaryHighlighting_InteractionWithPrimaryHighlighting_LeftClick() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		ClangToken token = getToken();
		String text = token.getText();
		assertEquals("_printf", text);

		Color color = highlight();
		assertAllFieldsSecondaryHighlighted(token, color);

		setDecompilerLocation(line, charPosition + 1);
		assertCombinedHighlightColor(token);

		// 2:1 "void"
		line = 2;
		charPosition = 1;
		setDecompilerLocation(line, charPosition);
		ClangToken token3 = getToken();
		String text3 = token3.getText();
		assertEquals("void", text3);
		assertPrimaryHighlight(token3);

		// secondary highlight was restored
		assertAllFieldsHighlighted(text, color);
	}

	@Test
	public void testSecondaryHighlighting_ForwardSliceDoesNotClearSecondaryHighlight() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		ClangToken token = getToken();
		String secondaryHighlightText = token.getText();
		assertEquals("_printf", secondaryHighlightText);

		Color color = highlight();

		// 10:19 "&a"
		line = 10;
		charPosition = 19;
		setDecompilerLocation(line, charPosition);

		backwardSlice();
		token = getToken();
		assertAllFieldsPrimaryHighlighted(token.getText());
		assertAllFieldsHighlighted(secondaryHighlightText, color);
	}

	@Test
	public void testSecondaryHighlighting_CombinedWithPrimaryHighlight() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		ClangToken token = getToken();
		String secondaryHighlightText = token.getText();
		assertEquals("_printf", secondaryHighlightText);

		Color color = highlight();

		// 6:2 "_printf"
		line = 6;
		charPosition = 2;
		setDecompilerLocation(line, charPosition);

		token = getToken();
		assertCombinedHighlightColor(token);
		assertAllFieldsSecondaryHighlighted(token, color);

		// no click away and make sure the secondary highlight color returns
		// 10:19 "&a"
		line = 10;
		charPosition = 19;
		setDecompilerLocation(line, charPosition);
		assertAllFieldsHighlighted(secondaryHighlightText, color);
	}

	@Test
	public void testSecondaryHighlighting_MiddleMouseDoesNotClearSecondaryHighlight() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		ClangToken token = getToken();
		String tokenText = token.getText();
		assertEquals("_printf", tokenText);

		Color color = highlight();

		middleMouse();
		assertCombinedHighlightColor(token);

		middleMouse();
		assertAllFieldsHighlighted(tokenText, color);
	}

	@Test
	public void testSecondaryHighlighting_CloneDecompiler() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);
		ClangToken token = getToken();
		String secondaryHighlightText = token.getText();
		assertEquals("_printf", secondaryHighlightText);

		Color color = highlight();

		DecompilerProvider clone = cloneDecompiler();
		ClangToken cloneToken = getToken(clone);
		assertAllFieldsSecondaryHighlighted(clone, cloneToken, color);

		// ensure one field provider does not affect the other
		removeSecondaryHighlight();
		assertNoFieldsSecondaryHighlighted(secondaryHighlightText);
		assertAllFieldsSecondaryHighlighted(clone, cloneToken, color);
	}

	@Test
	public void testSecondaryHighlighting_ChooseColors() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);
		ClangToken token = getToken();
		String secondaryHighlightText = token.getText();
		assertEquals("_printf", secondaryHighlightText);

		Color myColor = Color.PINK;
		highlightWithColorChooser(myColor);
		assertAllFieldsSecondaryHighlighted(token, myColor);
	}

	@Test
	public void testSecondaryHighlighting_ChooseColors_ColorIsLaterReusedForSameToken() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);
		ClangToken token = getToken();
		String secondaryHighlightText = token.getText();
		assertEquals("_printf", secondaryHighlightText);

		Color myColor = Color.PINK;
		highlightWithColorChooser(myColor);

		removeSecondaryHighlight();

		Color hlColor2 = highlight();
		assertEquals(myColor, hlColor2);
	}

	@Test
	public void testSecondaryHighlighting_GetsReappliedAfterRefresh() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);
		ClangToken token = getToken();

		Color color = highlight();
		assertAllFieldsSecondaryHighlighted(token, color);

		refresh();

		setDecompilerLocation(line, charPosition);
		token = getToken();
		assertAllFieldsSecondaryHighlighted(token, color);
	}

	@Test
	public void testSecondaryHighlighting_GetsReappliedAfterReturningToPreviousFunction() {

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

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);
		ClangToken token = getToken();

		Color color = highlight();
		assertAllFieldsSecondaryHighlighted(token, color);

		decompile("100000bf0"); // 'main'
		assertNoFieldsSecondaryHighlighted(token.getText());

		decompile("100000d60"); // '_call_structure_A'
		setDecompilerLocation(line, charPosition);
		token = getToken();
		assertAllFieldsSecondaryHighlighted(token, color);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void refresh() {

		DockingActionIf action = getAction(decompiler, "Refresh");
		performAction(action, provider.getActionContext(null), true);
		waitForDecompiler();
	}

	private DecompilerProvider cloneDecompiler() {

		DockingActionIf action = getAction(decompiler, "Decompile Clone");
		performAction(action, provider.getActionContext(null), true);
		waitForSwing();

		@SuppressWarnings("unchecked")
		List<DecompilerProvider> disconnectedProviders =
			(List<DecompilerProvider>) getInstanceField("disconnectedProviders", decompiler);
		assertFalse(disconnectedProviders.isEmpty());
		return disconnectedProviders.get(0);
	}

	private void assertPrimaryHighlights(String text) {
		List<ClangToken> tokens = getPrimaryHighlightTokens();
		StringBuilder buffy = new StringBuilder();
		for (ClangToken token : tokens) {
			buffy.append(token.getText());
		}

		assertEquals(text, buffy.toString());
	}

	private void assertCombinedHighlightColor(ClangToken token) {

		Color combinedColor = getCombinedHighlightColor(token);
		Color actual = token.getHighlight();
		assertEquals(combinedColor, actual);
	}

	private Color getDefaultHighlightColor() {

		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		Color c = panel.getCurrentVariableHighlightColor();
		return c;
	}

	private Color getSpecialHighlightColor() {

		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		Color c = panel.getSpecialHighlightColor();
		return c;
	}

	private Color getMiddleMouseHighlightColor() {

		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		Color c = panel.getMiddleMouseHighlightColor();
		return c;
	}

	private Color getCombinedHighlightColor(ClangToken token) {
		return getCombinedHighlightColor(provider, token);
	}

	private Color getCombinedHighlightColor(DecompilerProvider theProvider, ClangToken token) {
		DecompilerPanel panel = theProvider.getDecompilerPanel();
		ClangHighlightController highlightController = panel.getHighlightController();
		return highlightController.getCombinedColor(token);
	}

	private List<ClangToken> getPrimaryHighlightTokens() {
		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		ClangHighlightController highlightController = panel.getHighlightController();
		TokenHighlights tokens = highlightController.getPrimaryHighlightedTokens();

		List<ClangToken> results = new ArrayList<>();
		for (HighlightToken hl : tokens) {
			results.add(hl.getToken());
		}

		results.sort((t1, t2) -> indexInParent(t1) - indexInParent(t2));
		return results;
	}

	private int indexInParent(ClangToken t) {
		ClangLine line = t.getLineParent();
		return line.indexOfToken(t);
	}

	private void backwardSlice() {
		DockingActionIf action = getAction(decompiler, BackwardsSliceAction.NAME);
		performAction(action, provider.getActionContext(null), true);
	}

	private void middleMouse() {
		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		FieldLocation location = panel.getCursorPosition();
		FieldPanel fp = panel.getFieldPanel();
		Field field = fp.getCurrentField();

		// x,y shouldn't matter
		int x = 0;
		int y = 0;
		int clickCount = 1;
		MouseEvent event = new MouseEvent(fp, 1, System.currentTimeMillis(), 0, x, y, clickCount,
			false, MouseEvent.BUTTON2);

		runSwing(() -> panel.buttonPressed(location, field, event));
	}

	private void assertPrimaryHighlight(ClangToken token) {
		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		Color hlColor = panel.getCurrentVariableHighlightColor();
		assertEquals(hlColor, token.getHighlight());
	}

	private void rename(String newName) {
		DockingActionIf action = getAction(decompiler, "Rename Variable");
		performAction(action, provider.getActionContext(null), false);

		InputDialog dialog = waitForDialogComponent(InputDialog.class);
		runSwing(() -> dialog.setValue(newName));

		pressButtonByText(dialog, "OK");
		waitForDecompiler();
	}

	private void clearAllHighlights() {

		DockingActionIf highlightAction =
			getAction(decompiler, RemoveAllSecondaryHighlightsAction.NAME);
		performAction(highlightAction, provider.getActionContext(null), true);
	}

	private Color highlight() {

		ClangToken token = getToken();

		DockingActionIf highlightAction = getAction(decompiler, SetSecondaryHighlightAction.NAME);
		performAction(highlightAction, provider.getActionContext(null), true);

		HighlightToken ht = getSecondaryHighlight(token);
		assertNotNull("No highlight for token: " + token, ht);
		return ht.getColor();
	}

	private HighlightToken getSecondaryHighlight(ClangToken token) {
		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		TokenHighlights highlights = panel.getSecondaryHighlightedTokens();
		HighlightToken ht = highlights.get(token);
		return ht;
	}

	private void highlightWithColorChooser(Color color) {

		ClangToken token = getToken();

		DockingActionIf highlightAction =
			getAction(decompiler, SetSecondaryHighlightColorChooserAction.NAME);
		performAction(highlightAction, provider.getActionContext(null), false);

		Window w = waitForWindow("Please Choose a Color");
		GhidraColorChooser colorChooser = findComponent(w, GhidraColorChooser.class);
		JButton okButton = findButtonByText(w, "OK");
		runSwing(() -> {
			colorChooser.setColor(color);
			okButton.doClick();
		});
		waitForSwing();

		HighlightToken ht = getSecondaryHighlight(token);
		assertNotNull("No highlight for token: " + token, ht);
		Color hlColor = ht.getColor();
		assertEquals(color, hlColor);
	}

	private void removeSecondaryHighlight() {

		ClangToken token = getToken();

		DockingActionIf highlightAction =
			getLocalAction(provider, RemoveSecondaryHighlightAction.NAME);
		performAction(highlightAction, provider.getActionContext(null), true);

		HighlightToken ht = getSecondaryHighlight(token);
		assertNull("Token should not be highlighted - '" + token + "': ", ht);
	}

	private void assertAllFieldsPrimaryHighlighted(String name) {

		Color hlColor = getDefaultHighlightColor();
		Color specialColor = getSpecialHighlightColor();

		ColorMatcher cm = new ColorMatcher(hlColor, specialColor);
		Predicate<ClangToken> noIgnores = t -> false;
		assertAllFieldsHighlighted(name, cm, noIgnores);
	}

	private void assertAllFieldsSecondaryHighlighted(ClangToken token, Color color) {
		Predicate<ClangToken> ignores = t -> t == token;
		String name = token.getText();
		assertAllFieldsHighlighted(name, color, ignores);

		// test the token under the cursor directly, as that may have a combined highlight applied
		Color combinedColor = getCombinedHighlightColor(token);
		ColorMatcher cm = new ColorMatcher(color, combinedColor);
		Color actual = token.getHighlight();
		assertTrue("Token is not highlighted: '" + token + "'" + "\n\texpected: " + cm +
			"; found: " + toString(actual), cm.matches(actual));
	}

	private void assertNoFieldsSecondaryHighlighted(String name) {
		Color defaultHlColor = getDefaultHighlightColor();
		Color specialHlColor = getSpecialHighlightColor();
		Color middleMouseHlColor = getMiddleMouseHighlightColor();
		ColorMatcher allowedColors =
			new ColorMatcher(defaultHlColor, specialHlColor, middleMouseHlColor, null);
		Predicate<ClangToken> noIgnores = t -> false;
		assertAllFieldsHighlighted(name, allowedColors, noIgnores);
	}

	private void assertAllFieldsHighlighted(String name, Color hlColor) {

		Predicate<ClangToken> noIgnores = t -> false;
		assertAllFieldsHighlighted(name, hlColor, noIgnores);
	}

	private void assertAllFieldsHighlighted(String name, Color color,
			Predicate<ClangToken> ignore) {

		ColorMatcher cm = new ColorMatcher(color);
		assertAllFieldsHighlighted(name, cm, ignore);
	}

	private void assertAllFieldsHighlighted(String name, ColorMatcher colorMatcher,
			Predicate<ClangToken> ignore) {
		assertAllFieldsHighlighted(provider, name, colorMatcher, ignore);
	}

	private void assertAllFieldsSecondaryHighlighted(DecompilerProvider theProvider,
			ClangToken token, Color color) {

		Predicate<ClangToken> ignores = t -> t == token;
		String name = token.getText();
		Color combinedColor = getCombinedHighlightColor(theProvider, token);
		ColorMatcher cm = new ColorMatcher(color, combinedColor);
		assertAllFieldsHighlighted(theProvider, name, cm, ignores);

		// test the token under the cursor directly, as that may have a combined highlight applied		
		Color actual = token.getHighlight();
		assertTrue("Token is not highlighted: '" + token + "'" + "\n\texpected: " + cm +
			"; found: " + toString(actual), cm.matches(actual));
	}

	private void assertAllFieldsHighlighted(DecompilerProvider theProvider, String name,
			ColorMatcher colorMatcher, Predicate<ClangToken> ignore) {

		DecompilerController controller = theProvider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		List<ClangToken> tokensWithName = panel.findTokensByName(name);
		for (ClangToken otherToken : tokensWithName) {
			if (ignore.test(otherToken)) {
				continue;
			}

			Color actual = otherToken.getHighlight();
			assertTrue("Token is not highlighted: '" + otherToken + "'" + "\n\texpected: " +
				colorMatcher + "; found: " + toString(actual), colorMatcher.matches(actual));
		}
	}

	private String toString(Color c) {
		if (c == null) {
			return "Color{null}";
		}
		int r = c.getRed();
		int g = c.getGreen();
		int b = c.getBlue();
		int a = c.getAlpha();
		// "Color[r=" + r +",g=" + g  +",b=" + b + ",a="+ a + "]"
		// "Color[r=%s,g=%s,b=%s,a=%s]"
		String formatted = String.format("Color{%s, %s, %s, %s}", r, g, b, a);
		return formatted;
	}

	private void copy() {

		Set<DockingActionIf> actions = getActionsByOwnerAndName(tool, "ClipboardPlugin", "Copy");
		for (DockingActionIf action : actions) {
			Object service = getInstanceField("clipboardService", action);
			if (service.getClass().toString().contains("Decomp")) {
				performAction(action, provider.getActionContext(null), true);
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
		ClangTextField field = getFieldForIndex(loc.getIndex().intValue());
		return field;
	}

	private void assertDisplayText(String expected, int line) {
		FieldLocation loc = loc(line, 0 /*column*/);
		ClangTextField field = getFieldForIndex(loc.getIndex().intValue());
		String actual = field.getText();
		assertEquals("Line text not as expected at line " + line, expected, actual);
	}

	private void assertCurrentLocation(int line, int col) {
		DecompilerPanel panel = provider.getDecompilerPanel();
		FieldLocation actual = panel.getCursorPosition();
		FieldLocation expected = loc(line, col);
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

	private class ColorMatcher {

		private Set<Color> myColors = new HashSet<>();

		ColorMatcher(Color... colors) {
			// note: we allow null

			for (Color c : colors) {
				myColors.add(c);
			}
		}

		public boolean matches(Color otherColor) {
			for (Color c : myColors) {
				if (Objects.equals(c, otherColor)) {
					return true;
				}
			}
			return false;
		}

		@Override
		public String toString() {
			//@formatter:off
			return myColors
					.stream()
					.map(c -> DecompilerClangTest.this.toString(c))
					.collect(Collectors.joining(","))
					;
			//@formatter:on
		}
	}
}
