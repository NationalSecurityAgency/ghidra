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
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.junit.Test;

import docking.action.DockingActionIf;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.decompile.actions.*;
import ghidra.program.model.listing.CodeUnit;

public class DecompilerClangTest extends AbstractDecompilerTest {

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
		assertAllFieldsHighlightedExceptForToken(token1, color);

		// 5:30 "a->name"
		line = 5;
		charPosition = 38;
		setDecompilerLocation(line, charPosition);
		ClangToken token2 = getToken();
		String text2 = token2.getText();
		assertEquals("name", text2);

		Color color2 = highlight();
		assertAllFieldsHighlighted(text1, color);
		assertAllFieldsHighlightedExceptForToken(token2, color2);

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
		assertAllFieldsHighlightedExceptForToken(token3, color3);
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
		clearSecondaryHighlight();

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
		assertAllFieldsHighlightedExceptForToken(token, color);
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

		clearSecondaryHighlight();

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
		assertAllFieldsHighlightedExceptForToken(token, color);

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
		assertAllFieldsHighlightedExceptForToken(token, color);

		// no click away and make sure the secondary highlight color returns
		// 10:19 "&a"
		line = 10;
		charPosition = 19;
		setDecompilerLocation(line, charPosition);
		assertAllFieldsHighlighted(secondaryHighlightText, color);
	}

	// TODO how does highlight interplay with slice highlight?	
	// -toggling a color highlight should not remove the other highlights
	// --test on and off
	// -test setting primary highlight does not clear secondary highlights
	//  -- secondary remains after clicking away
	//  --middle-mouse
	//  --slicing

	// TODO test highlights passed to clone

	// TODO allow for any text, not just variables?
	// TODO - follow-up test that 2 variables with the same name do not get highlighted

	// TODO test color chooser

	// TODO test persistence
	// TODO Energy
	//  		-highlight tokens between parens

	// TODO test clone copies highlights

//==================================================================================================
// Private Methods
//==================================================================================================

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
		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		ClangHighlightController highlightController = panel.getHighlightController();
		return highlightController.getCombinedColor(token);
	}

	private void backwardSlice() {
		DockingActionIf action = getAction(decompiler, BackwardsSliceAction.NAME);
		performAction(action);
	}

	private void assertPrimaryHighlight(ClangToken token) {
		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		Color hlColor = panel.getCurrentVariableHighlightColor();
		assertEquals(hlColor, token.getHighlight());
	}

	private void assertPrimaryAndSecondaryHighlight(ClangToken token) {
		// TODO Auto-generated method stub
		fail();
	}

	private void rename(String newName) {
		DockingActionIf action = getAction(decompiler, "Rename Variable");
		performAction(action, false);

		InputDialog dialog = waitForDialogComponent(InputDialog.class);
		runSwing(() -> dialog.setValue(newName));

		pressButtonByText(dialog, "OK");
		waitForDecompiler();
	}

	private void clearAllHighlights() {

		DockingActionIf highlightAction =
			getAction(decompiler, RemoveSecondaryHighlightsAction.NAME);
		performAction(highlightAction);
	}

	private Color highlight() {

		ClangToken token = getToken();

		DockingActionIf highlightAction =
			getAction(decompiler, ToggleSecondaryHighlightAction.NAME);
		performAction(highlightAction);

		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		TokenHighlights highlights = panel.getSecondaryHighlightedTokens();
		HighlightToken ht = highlights.get(token);
		assertNotNull("No highlight for token: " + token, ht);
		return ht.getColor();
	}

	private void clearSecondaryHighlight() {

		ClangToken token = getToken();

		DockingActionIf highlightAction =
			getAction(decompiler, ToggleSecondaryHighlightAction.NAME);
		performAction(highlightAction);

		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		TokenHighlights highlights = panel.getSecondaryHighlightedTokens();
		HighlightToken ht = highlights.get(token);
		assertNull("Token should not be highlighted: " + token, ht);
	}

	private void assertAllFieldsPrimaryHighlighted(String name) {

		Color hlColor = getDefaultHighlightColor();
		Color specialColor = getSpecialHighlightColor();

		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		List<ClangToken> tokensWithName = panel.findTokensByName(name);
		assertFalse(tokensWithName.isEmpty());
		for (ClangToken otherToken : tokensWithName) {

			Color tokenColor = otherToken.getHighlight();
			boolean yes = hlColor.equals(tokenColor) || specialColor.equals(tokenColor);

			assertTrue("Token is not highlighted: '" + otherToken + "'" + "\n\texpected: " +
				toString(hlColor) + "; found: " + toString(otherToken.getHighlight()), yes);
		}
	}

	private void assertAllFieldsHighlightedExceptForToken(ClangToken token, Color color) {
		Predicate<ClangToken> ignores = t -> t == token;
		String name = token.getText();
		assertAllFieldsHighlighted(name, color, ignores);
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
		DecompilerController controller = provider.getController();
		DecompilerPanel panel = controller.getDecompilerPanel();
		List<ClangToken> tokensWithName = panel.findTokensByName(name);
		assertFalse(tokensWithName.isEmpty());
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
