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
package ghidra.app.decompiler.component;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.swing.*;

import org.junit.Before;
import org.junit.Test;

import docking.action.DockingActionIf;
import docking.options.editor.GhidraColorChooser;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.DecompileOptions.NamespaceStrategy;
import ghidra.app.plugin.core.decompile.AbstractDecompilerTest;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.decompile.actions.*;
import ghidra.app.util.AddEditDialog;
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
			 2| int _main(int argc,char **argv)
			 3|
			 4| {
			 5|   _a.id = 1;
			 6|   _a.name = "A";
			 7|   _b.id = 2;
			 8|   _b.name = "B";
			 9|   _c.id = 3;
			10|   _c.name = "C";
			11|   _d.id = 4;
			12|   _d.name = "D";
			13|   _e.id = 5;
			14|   _e.name = "E";
			15|   _c.d.e._4_4_ = _e._4_4_;
			16|   _c.d.e.id = 5;
			17|   _d.e.name = "E";
			18|   _c.d._4_4_ = _d._4_4_;
			19|   _c.d.id = 4;
			20|   _c.d.name = "D";
			21|   _c.d.e.name = "E";
			22|   _d.e._0_8_ = _c.d.e._0_8_;
			23|   __stubs::_memcpy(&_b.c,&_c,0x30);
			24|   __stubs::_memcpy(&_a.b,&_b,0x40);
			25|   _call_structure_A(&_a);
			26|   return 0;
			27| }
		 	
		 */

		decompile("100000bf0"); // 'main'

		/*
		 	26: return 0;
		 */
		int line = 26;
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
		 2| int _main(int argc,char **argv)
		 3|
		 4| {
		 5|   _a.id = 1;
		 6|   _a.name = "A";
		 7|   _b.id = 2;
		 8|   _b.name = "B";
		 9|   _c.id = 3;
		10|   _c.name = "C";
		11|   _d.id = 4;
		12|   _d.name = "D";
		13|   _e.id = 5;
		14|   _e.name = "E";
		15|   _c.d.e._4_4_ = _e._4_4_;
		16|   _c.d.e.id = 5;
		17|   _d.e.name = "E";
		18|   _c.d._4_4_ = _d._4_4_;
		19|   _c.d.id = 4;
		20|   _c.d.name = "D";
		21|   _c.d.e.name = "E";
		22|   _d.e._0_8_ = _c.d.e._0_8_;
		23|   __stubs::_memcpy(&_b.c,&_c,0x30);
		24|   __stubs::_memcpy(&_a.b,&_b,0x40);
		25|   _call_structure_A(&_a);
		26|   return 0;
		27| }
		
		*/
		decompile("100000bf0"); // 'main'

		/*
		 	26: return 0;
		 */
		int line = 26;
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
	public void testSecondaryHighlighting_ClearAll_DoesNotAffectOtherFunctions() {

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
		   
		   
		Decomp of '_call_structure_B':
			
			1|
			2| void _call_structure_B(B *b)
			3|
			4| {
			5|   	_printf("call_structure_B: %s\n",b->name);
			6|   	_call_structure_C(&b->c);
			7|   	return;
			8| }
		
		
		
		 */

		decompile("100000d60"); // '_call_structure_A'

		// 5:2 "_printf"
		int line1 = 5;
		int charPosition1 = 2;
		setDecompilerLocation(line1, charPosition1);
		ClangToken token1 = getToken();

		Color color1 = highlight();
		assertAllFieldsSecondaryHighlighted(token1, color1);

		decompile("100000e10"); // '_call_structure_B'

		// 5:2 "_printf"
		int line2 = 5;
		int charPosition2 = 2;
		setDecompilerLocation(line2, charPosition2);
		ClangToken token2 = getToken();

		Color color2 = highlight();
		assertAllFieldsSecondaryHighlighted(token2, color2);

		decompile("100000d60"); // '_call_structure_A'

		// 5:2 "_printf"
		setDecompilerLocation(line1, charPosition1);
		clearAllHighlights();

		// token 1 cleared; token 2 still highlighted
		assertNoFieldsSecondaryHighlighted(token1.getText());

		decompile("100000e10"); // '_call_structure_B'
		setDecompilerLocation(line2, charPosition2);
		token2 = getToken();
		assertAllFieldsSecondaryHighlighted(token2, color2);
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
	public void testSecondaryHighlighting_RenameHighlightedFunction() {

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

		renameFunction("bob");

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

		Color myColor = Palette.PINK;
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

		Color myColor = Palette.PINK;
		highlightWithColorChooser(myColor);

		removeSecondaryHighlight();

		Color hlColor2 = highlight();
		assertEquals(myColor.getRGB(), hlColor2.getRGB());
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

	@Test
	public void testSecondaryHighlighting_DoesNotApplyToOtherFunctions() {

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
		
		Decomp of '_call_structure_B':
			
			1|
			2| void _call_structure_B(B *b)
			3|
			4| {
			5|   	_printf("call_structure_B: %s\n",b->name);
			6|   	_call_structure_C(&b->c);
			7|   	return;
			8| }
		
		
		
		 */

		decompile("100000d60"); // '_call_structure_A'

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);
		ClangToken token = getToken();

		Color color = highlight();
		assertAllFieldsSecondaryHighlighted(token, color);

		decompile("100000e10"); // '_call_structure_B'
		assertNoFieldsSecondaryHighlighted(token.getText());
	}

	@Test
	public void testHighlightService() {

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

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter = hlService.createHighlighter(spyMatcher);
		highlighter.applyHighlights();

		assertTrue(spyMatcher.getMatchingTokens().size() > 0);
		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);

		highlighter.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);
	}

	@Test
	public void testHighlightService_WithPrimaryHighlights() {

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

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter = hlService.createHighlighter(spyMatcher);
		highlighter.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);
		assertPrimaryHighlights("(\"call_structure_A: %s\\n\",a->name)");

		highlighter.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);
		assertPrimaryHighlights("(\"call_structure_A: %s\\n\",a->name)");
	}

	@Test
	public void testHighlightService_WithSecondaryighlights_NoOverlappingMatches() {

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

		//
		// This test will add a 'secondary highlight' to the "_printf" token and will also use the
		// highlight service to add a highlighter highlight for that same token
		//

		// 5:38 "name"
		int line = 5;
		int charPosition = 38;
		setDecompilerLocation(line, charPosition);

		ClangToken secondrayToken = getToken();
		String text = secondrayToken.getText();
		assertEquals("name", text);

		Color secondaryHlColor = highlight();
		assertAllFieldsSecondaryHighlighted(secondrayToken, secondaryHlColor);

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter = hlService.createHighlighter(spyMatcher);
		highlighter.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);
		assertAllFieldsSecondaryHighlighted(secondrayToken, secondaryHlColor);

		highlighter.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);
		assertAllFieldsSecondaryHighlighted(secondrayToken, secondaryHlColor);
	}

	@Test
	public void testHighlightService_WithSecondaryighlights_WithOverlappingMatches() {

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

		//
		// This test will add a 'secondary highlight' to the "_printf" token and will also use the
		// highlight service to add a highlighter highlight for that same token
		//

		// 5:2 "_printf"
		int line = 5;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		ClangToken secondaryToken = getToken();
		String secondaryText = secondaryToken.getText();
		assertEquals("_printf", secondaryText);

		Color secondaryHlColor = highlight();
		assertAllFieldsSecondaryHighlighted(secondaryToken, secondaryHlColor);

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter = hlService.createHighlighter(spyMatcher);
		highlighter.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);

		Color combinedColor = getCombinedHighlightColor(secondaryToken);
		ColorMatcher cm = new ColorMatcher(hlColor, secondaryHlColor, combinedColor);
		Predicate<ClangToken> ignore = t -> t == secondaryToken;
		assertAllSecondaryAndHighlighterFieldsHighlighted(provider, hlText, cm, ignore);

		highlighter.clearHighlights();
		assertAllFieldsSecondaryHighlighted(secondaryToken, secondaryHlColor);
	}

	@Test
	public void testHighlightService_MultipleHighlighters_NoOverlappingMatches() {

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

		String hlText1 = "_printf";
		Color hlColor1 = Palette.PINK;
		CTokenHighlightMatcher hlMatcher1 = token -> {
			if (token.getText().contains(hlText1)) {
				return hlColor1;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher1 = new SpyCTokenHighlightMatcher(hlMatcher1);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter1 = hlService.createHighlighter(spyMatcher1);
		highlighter1.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher1, hlText1, hlColor1);

		highlighter1.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText1);

		String hlText2 = "name";
		Color hlColor2 = Palette.GREEN;
		CTokenHighlightMatcher hlMatcher2 = token -> {
			if (token.getText().contains(hlText2)) {
				return hlColor2;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher2 = new SpyCTokenHighlightMatcher(hlMatcher2);
		DecompilerHighlighter highlighter2 = hlService.createHighlighter(spyMatcher2);
		highlighter2.applyHighlights();

		Color combinedColor = getBlendedColor(hlColor1, hlColor2);
		assertAllHighlighterFieldsHighlighted(spyMatcher1, hlText1, combinedColor);
		assertAllHighlighterFieldsHighlighted(spyMatcher2, hlText2, combinedColor);

		highlighter1.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText1);
		assertAllHighlighterFieldsHighlighted(spyMatcher2, hlText2, combinedColor);

		highlighter2.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText2);
	}

	@Test
	public void testHighlightService_MultipleHighlighters_WithOverlappingMatches() {

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

		String hlText = "_printf";
		Color hlColor1 = Palette.PINK;
		CTokenHighlightMatcher hlMatcher1 = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor1;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher1 = new SpyCTokenHighlightMatcher(hlMatcher1);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter1 = hlService.createHighlighter(spyMatcher1);
		highlighter1.applyHighlights();

		Color hlColor2 = Palette.GREEN;
		CTokenHighlightMatcher hlMatcher2 = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor2;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher2 = new SpyCTokenHighlightMatcher(hlMatcher2);
		DecompilerHighlighter highlighter2 = hlService.createHighlighter(spyMatcher2);
		highlighter2.applyHighlights();

		Color combinedColor = getBlendedColor(hlColor1, hlColor2);
		assertAllHighlighterFieldsHighlighted(spyMatcher1, hlText, combinedColor);
		assertAllHighlighterFieldsHighlighted(spyMatcher2, hlText, combinedColor);
		assertPrimaryHighlights("(\"call_structure_A: %s\\n\",a->name)");

		highlighter1.clearHighlights();
		assertAllHighlighterFieldsHighlighted(spyMatcher2, hlText, hlColor2);

		highlighter2.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);
		assertPrimaryHighlights("(\"call_structure_A: %s\\n\",a->name)");
	}

	@Test
	public void testHighlightService_Dispose() {

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

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter = hlService.createHighlighter(spyMatcher);
		highlighter.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);

		highlighter.dispose();
		assertNoFieldsSecondaryHighlighted(hlText);

		// no effect calling apply after dispose
		highlighter.applyHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);
	}

	@Test
	public void testHighlightService_CreateWithId() {

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

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher1 = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		String id = "TestId";
		DecompilerHighlighter highlighter = hlService.createHighlighter(id, spyMatcher1);
		highlighter.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher1, hlText, hlColor);

		highlighter.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);

		SpyCTokenHighlightMatcher spyMatcher2 = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlighter newHighlighter = hlService.createHighlighter(id, spyMatcher2);
		newHighlighter.applyHighlights();
		assertAllHighlighterFieldsHighlighted(spyMatcher2, hlText, hlColor);

		newHighlighter.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);

		// make sure calls to the original highlighter no longer work, as it has been removed
		spyMatcher1.clear();
		highlighter.applyHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);

	}

	@Test
	public void testHighlightService_CloneDecompiler_HighlighterApplied() {

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

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter = hlService.createHighlighter(spyMatcher);
		highlighter.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);

		DecompilerProvider clone = cloneDecompiler();
		DecompilerHighlighter cloneHighlighter = getHighlighter(clone, highlighter.getId());
		assertAllHighlighterFieldsHighlighted(clone, cloneHighlighter, spyMatcher, hlText, hlColor);

		highlighter.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);
		assertNoFieldsSecondaryHighlighted(clone, hlText);
	}

	@Test
	public void testHighlightService_CloneDecompiler_HighlightsUpdated() {

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

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter = hlService.createHighlighter(spyMatcher);
		DecompilerProvider clone = cloneDecompiler();
		assertNoFieldsSecondaryHighlighted(hlText);
		assertNoFieldsSecondaryHighlighted(clone, hlText);

		highlighter.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);
		DecompilerHighlighter cloneHighlighter = getHighlighter(clone, highlighter.getId());
		assertAllHighlighterFieldsHighlighted(clone, cloneHighlighter, spyMatcher, hlText, hlColor);

		highlighter.clearHighlights();
		assertNoFieldsSecondaryHighlighted(hlText);
		assertNoFieldsSecondaryHighlighted(clone, hlText);
	}

	@Test
	public void testHighlightService_CloneDecompiler_RemoveHighlighter() {

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

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter = hlService.createHighlighter(spyMatcher);
		highlighter.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);

		DecompilerProvider clone = cloneDecompiler();
		DecompilerHighlighter cloneHighlighter = getHighlighter(clone, highlighter.getId());
		assertAllHighlighterFieldsHighlighted(clone, cloneHighlighter, spyMatcher, hlText, hlColor);

		highlighter.dispose();
		assertNoFieldsSecondaryHighlighted(hlText);
		assertNoFieldsSecondaryHighlighted(clone, hlText);
	}

	@Test
	public void testHighlightService_NewFunctionReappliesHighlights() {

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

		String hlText = "_printf";
		Color hlColor = Palette.PINK;
		CTokenHighlightMatcher hlMatcher = token -> {
			if (token.getText().contains(hlText)) {
				return hlColor;
			}
			return null;
		};
		SpyCTokenHighlightMatcher spyMatcher = new SpyCTokenHighlightMatcher(hlMatcher);
		DecompilerHighlightService hlService = getHighlightService();
		DecompilerHighlighter highlighter = hlService.createHighlighter(spyMatcher);
		highlighter.applyHighlights();

		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);

		spyMatcher.clear();

		// this function also has calls to '_printf'
		decompile("100000e10"); // '_call_structure_B'

		assertTrue(spyMatcher.getMatchingTokens().size() > 0);
		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, hlColor);

		highlighter.dispose();
		assertNoFieldsSecondaryHighlighted(hlText);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private DecompilerHighlighter getHighlighter(DecompilerProvider clone, String id) {
		DecompilerPanel clonePanel = clone.getController().getDecompilerPanel();
		return clonePanel.getHighlighter(id);
	}

	private DecompilerHighlightService getHighlightService() {
		return provider;
	}

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

	private Color getBlendedColor(Color... colors) {
		DecompilerPanel panel = provider.getController().getDecompilerPanel();
		ClangHighlightController highlightController = panel.getHighlightController();
		List<Color> colorList = Arrays.asList(colors);
		return highlightController.blend(colorList);
	}

	private Color getCombinedHighlightColor(ClangToken token) {
		return getCombinedHighlightColor(provider, token);
	}

	private Color getCombinedHighlightColor(DecompilerProvider theProvider, ClangToken token) {
		DecompilerPanel panel = theProvider.getController().getDecompilerPanel();
		ClangHighlightController highlightController = panel.getHighlightController();
		return highlightController.getCombinedColor(token);
	}

	private List<ClangToken> getPrimaryHighlightTokens() {
		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		ClangHighlightController highlightController = panel.getHighlightController();
		TokenHighlights tokens = highlightController.getPrimaryHighlights();

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

	private void renameFunction(String newName) {
		DockingActionIf action = getAction(decompiler, "Rename Function");
		performAction(action, provider.getActionContext(null), false);

		AddEditDialog dialog = waitForDialogComponent(AddEditDialog.class);
		runSwing(() -> {
			JComboBox<?> comboBox =
				(JComboBox<?>) findComponentByName(dialog, "label.name.choices");
			Component comp = comboBox.getEditor().getEditorComponent();
			((JTextField) comp).setText(newName);
		});

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

		Color color = getSecondaryHighlight(token);
		assertNotNull("No highlight for token: " + token, color);
		return color;
	}

	private Color getSecondaryHighlight(ClangToken token) {
		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		return panel.getSecondaryHighlight(token);
	}

	private TokenHighlights getHighligtedTokens(DecompilerProvider theProvider,
			DecompilerHighlighter highlighter) {
		DecompilerController controller = theProvider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		return panel.getHighlights(highlighter);
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

		Color hlColor = getSecondaryHighlight(token);
		assertNotNull("No highlight for token: " + token, hlColor);
		assertEquals(color.getRGB(), hlColor.getRGB());
	}

	private void removeSecondaryHighlight() {

		ClangToken token = getToken();

		DockingActionIf highlightAction =
			getLocalAction(provider, RemoveSecondaryHighlightAction.NAME);
		performAction(highlightAction, provider.getActionContext(null), true);

		Color color = getSecondaryHighlight(token);
		assertNull("Token should not be highlighted - '" + token + "': ", color);
	}

	private void assertAllFieldsPrimaryHighlighted(String name) {

		Color hlColor = getDefaultHighlightColor();
		Color specialColor = getSpecialHighlightColor();

		ColorMatcher cm = new ColorMatcher(hlColor, specialColor);
		Predicate<ClangToken> noIgnores = t -> false;
		assertAllFieldsHighlighted(name, cm, noIgnores);
	}

	private void assertAllHighlighterFieldsHighlighted(SpyCTokenHighlightMatcher spyMatcher,
			String hlText, Color hlColor) {

		ClangToken cursorToken = getToken(provider);
		Predicate<ClangToken> ignores = t -> t == cursorToken;
		assertAllHighlighterFieldsHighlighted(spyMatcher, hlText, ignores);
	}

	private void assertAllHighlighterFieldsHighlighted(DecompilerProvider theProvider,
			DecompilerHighlighter highlighter, SpyCTokenHighlightMatcher matcher, String matchText,
			Color color) {

		ClangToken cursorToken = getToken(theProvider);
		Predicate<ClangToken> ignores = t -> t == cursorToken;
		assertAllHighlighterFieldsHighlighted(theProvider, highlighter, matcher, matchText,
			ignores);

		// test the token under the cursor directly, as that may have a combined highlight applied
		Color combinedColor = getCombinedHighlightColor(theProvider, cursorToken);
		ColorMatcher cm = new ColorMatcher(color, combinedColor);
		Color actual = cursorToken.getHighlight();
		assertTrue("Token is not highlighted: '" + cursorToken + "'" + "\n\texpected: " + cm +
			"; found: " + toString(actual), cm.matches(actual));
	}

	private void assertAllFieldsSecondaryHighlighted(ClangToken token, Color color) {
		String name = token.getText();
		assertAllFieldsSecondaryHighlighted(token, name, color);
	}

	private void assertAllFieldsSecondaryHighlighted(ClangToken token, String matchText,
			Color color) {
		Predicate<ClangToken> ignores = t -> t == token;
		assertAllFieldsHighlighted(matchText, color, ignores);

		// test the token under the cursor directly, as that may have a combined highlight applied
		Color combinedColor = getCombinedHighlightColor(token);
		ColorMatcher cm = new ColorMatcher(color, combinedColor);
		Color actual = token.getHighlight();
		String tokenString = token.toString() + " at line " + token.getLineParent().getLineNumber();
		assertTrue("Token is not highlighted: '" + tokenString + "'" + "\n\texpected: " + cm +
			"; found: " + toString(actual), cm.matches(actual));
	}

	private void assertNoFieldsSecondaryHighlighted(String hlText) {
		assertNoFieldsSecondaryHighlighted(provider, hlText);
	}

	private void assertNoFieldsSecondaryHighlighted(DecompilerProvider theProvider, String hlText) {
		Color defaultHlColor = getDefaultHighlightColor();
		Color specialHlColor = getSpecialHighlightColor();
		Color middleMouseHlColor = getMiddleMouseHighlightColor();
		ColorMatcher allowedColors =
			new ColorMatcher(defaultHlColor, specialHlColor, middleMouseHlColor, null);
		Predicate<ClangToken> noIgnores = t -> false;
		assertAllFieldsHighlighted(theProvider, hlText, allowedColors, noIgnores);
	}

	private void assertAllFieldsHighlighted(String name, Color hlColor) {

		Predicate<ClangToken> noIgnores = t -> false;
		assertAllFieldsHighlighted(name, hlColor, noIgnores);
	}

	private void assertAllFieldsHighlighted(String name, Color color,
			Predicate<ClangToken> ignore) {

		ColorMatcher cm = new ColorMatcher(color);
		assertAllFieldsHighlighted(provider, name, cm, ignore);
	}

	private void assertAllHighlighterFieldsHighlighted(SpyCTokenHighlightMatcher spyMatcher,
			String matchText, Predicate<ClangToken> ignore) {

		Map<ClangToken, Color> matchingTokens = spyMatcher.getMatchingTokens();
		for (Map.Entry<ClangToken, Color> entry : matchingTokens.entrySet()) {

			ClangToken token = entry.getKey();
			Color color = entry.getValue();
			Color combinedColor = getCombinedHighlightColor(token);
			ColorMatcher cm = new ColorMatcher(color, combinedColor);
			if (ignore.test(token)) {
				continue;
			}

			Color actual = token.getHighlight();
			assertTrue("Token is not highlighted: '" + token + "'" + "\n\texpected: " + cm +
				"; found: " + toString(actual), cm.matches(actual));
		}
	}

	private void assertAllHighlighterFieldsHighlighted(DecompilerProvider theProvider,
			DecompilerHighlighter decompilerHighlighter, SpyCTokenHighlightMatcher spyMatcher,
			String matchText, Predicate<ClangToken> ignore) {

		TokenHighlights providerHighlights =
			getHighligtedTokens(theProvider, decompilerHighlighter);
		assertNotNull("No highligts for highlighter in the given provider", providerHighlights);
		Map<ClangToken, Color> matchingTokens = spyMatcher.getMatchingTokens();

		for (Map.Entry<ClangToken, Color> entry : matchingTokens.entrySet()) {

			ClangToken token = entry.getKey();
			HighlightToken hlToken = providerHighlights.get(token);
			assertNotNull("Provider is missing highlighted token", hlToken);
			Color color = entry.getValue();
			Color combinedColor = getCombinedHighlightColor(theProvider, token);
			ColorMatcher cm = new ColorMatcher(color, combinedColor);
			if (ignore.test(token)) {
				continue;
			}

			Color actual = token.getHighlight();
			assertTrue("Token is not highlighted: '" + token + "'" + "\n\texpected: " + cm +
				"; found: " + toString(actual), cm.matches(actual));
		}
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

	private void assertAllSecondaryAndHighlighterFieldsHighlighted(DecompilerProvider theProvider,
			String name, ColorMatcher colorMatcher, Predicate<ClangToken> ignore) {

		DecompilerController controller = theProvider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		List<ClangToken> tokensWithName = panel.findTokensByName(name);
		for (ClangToken otherToken : tokensWithName) {
			if (ignore.test(otherToken)) {
				continue;
			}

			Color actual = otherToken.getHighlight();
			Color combinedColor = getCombinedHighlightColor(otherToken);
			ColorMatcher combinedColorMatcher = colorMatcher.with(combinedColor);
			assertTrue(
				"Token is not highlighted: '" + otherToken + "'" + "\n\texpected: " +
					combinedColorMatcher + "; found: " + toString(actual),
				combinedColorMatcher.matches(actual));
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
		DecompilerPanel panel = provider.getController().getDecompilerPanel();
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

		ColorMatcher with(Color c) {
			ColorMatcher newCm = new ColorMatcher(c);
			newCm.myColors.addAll(myColors);
			return newCm;
		}

		public boolean matches(Color otherColor) {
			for (Color c : myColors) {
				if (c == null) {
					if (otherColor == null) {
						return true;
					}
					continue;
				}
				if (otherColor == null) {
					continue;
				}

				if (c.getRGB() == otherColor.getRGB()) {
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

	private class SpyCTokenHighlightMatcher implements CTokenHighlightMatcher {

		private CTokenHighlightMatcher delegate;
		private Map<ClangToken, Color> highlightsByToken = new HashMap<>();

		SpyCTokenHighlightMatcher(CTokenHighlightMatcher delegate) {
			this.delegate = delegate;
		}

		Map<ClangToken, Color> getMatchingTokens() {
			return highlightsByToken;
		}

		void clear() {
			highlightsByToken.clear();
		}

		@Override
		public Color getTokenHighlight(ClangToken token) {
			Color hl = delegate.getTokenHighlight(token);
			if (hl != null) {
				highlightsByToken.put(token, hl);
			}
			return hl;
		}
	}
}
