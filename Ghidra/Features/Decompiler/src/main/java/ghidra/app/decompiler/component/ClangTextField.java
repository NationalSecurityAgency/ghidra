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

import java.awt.Graphics;
import java.awt.Rectangle;
import java.util.List;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.decompiler.ClangToken;

public class ClangTextField extends WrappingVerticalLayoutTextField {

	private List<ClangToken> tokenList;
	private FieldElement lineNumberFieldElement;

	private static FieldElement createSingleLineElement(FieldElement[] textElements) {
		return new CompositeFieldElement(textElements, 0, textElements.length);
	}

	/**
	 * Calculates the offset of the x position for the given line number element.  The line
	 * numbers of the decompiler appear to the left of the data and thus offset the actual data
	 * by the width of the line numbers.  The line numbers may be disabled, in which case the
	 * given FieldElement will have no width.
	 *
	 * @param initialX The original x value passed to the constructor of this class
	 * @param lineNumberElement he line number element for this field from which we get a width
	 * @return the calculated offset
	 */
	private static int calculateXPositionWithLineNumberOffset(int initialX,
			FieldElement lineNumberElement) {
		return initialX + lineNumberElement.getStringWidth();
	}

	/**
	 * Calculates the modified width for this field.  This is a factor of line numbers and any
	 * x offset given to this field element.
	 *
	 * @param initialX The original x value passed to the constructor of this class
	 * @param lineNumberElement The line number element for this field from which we get a width
	 * @param initialWidth The initial width we are allowed to take up
	 * @return the modified width for this field.  This is a factor of line numbers and any
	 *         x offset given to this field element.
	 */
	private static int calculateWidthFromXPosition(int initialX, FieldElement lineNumberElement,
			int initialWidth) {
		return initialWidth - calculateXPositionWithLineNumberOffset(initialX, lineNumberElement);
	}

	public ClangTextField(List<ClangToken> tokenList, FieldElement[] fieldElements,
			FieldElement lineNumberFieldElement, int x, int width, HighlightFactory hlFactory) {
		super(createSingleLineElement(fieldElements),
			calculateXPositionWithLineNumberOffset(x, lineNumberFieldElement),
			calculateWidthFromXPosition(x, lineNumberFieldElement, width), 30, hlFactory, false);
		this.tokenList = tokenList;
		this.lineNumberFieldElement = lineNumberFieldElement;
	}

	/**
	 * Gets the C language token at the indicated location.
	 * @param loc the field location
	 * @return the token
	 */
	public ClangToken getToken(FieldLocation loc) {
		if (loc == null) {
			return null;
		}

		FieldElement clickedObject = getClickedObject(loc);
		if (clickedObject instanceof ClangFieldElement) {
			ClangFieldElement element = (ClangFieldElement) clickedObject;
			return element.getToken();
		}

		int index = getTokenIndex(loc);
		return tokenList.get(index);
	}

	/**
	 * Returns the token that is completely after the token that contains the given column
	 * location.  In this case, 'contains' means any position <b>inside</b> of a token, but
	 * not at the beginning.  So, if the column location is in the middle of a
	 * token, it will return the index of next token. But if the column location is at
	 * the beginning (just before the start) of a token, it will return the index of that token.
	 *
	 * @param location containing the column at which to beginning searching
	 * @return the next token starting after the given column
	 */
	int getNextTokenIndexStartingAfter(FieldLocation location) {

		int n = 0;
		for (int i = 0; i < tokenList.size(); i++) {

			if (location.col == n) {
				// the start of the token means we are on the next token (just as with the
				// current token)
				return i;
			}

			ClangToken token = tokenList.get(i);
			int length = n + token.getText().length();
			if (length >= location.col) {
				return i + 1; // this will be an invalid index when at the end of the list
			}
			n = length;
		}

		return tokenList.size(); // at the end; return the size, as it is used 'exclusive'ly
	}

	int getTokenIndex(FieldLocation location) {

		int n = 0;
		for (int i = 0; i < tokenList.size(); i++) {

			if (location.col == n) {
				// this is needed because tokens can have zero-width so
				return i;
			}

			ClangToken token = tokenList.get(i);
			int length = n + token.getText().length();
			if (length > location.col) {
				return i;
			}
			n = length;
		}

		return tokenList.size() - 1; // at the end--return the last token index
	}

	FieldElement getClickedObject(FieldLocation fieldLocation) {
		return getFieldElement(fieldLocation.row, fieldLocation.col);
	}

	List<ClangToken> getTokens() {
		return tokenList;
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context, Rectangle clip,
			FieldBackgroundColorManager selectionMap, RowColLocation cursorLoc, int rowHeight) {

		// Don't print line numbers; don't copy line numbers.  We are assuming that the user only
		// wants to copy code.
		if (context.isPrinting() || context.isTextCopying()) {
			printTextWithoutLineNumbers(c, g, context, clip, selectionMap, cursorLoc, rowHeight);
			return;
		}

		// paint our line number
		lineNumberFieldElement.paint(c, g, 0, 0);
		super.paint(c, g, context, clip, selectionMap, cursorLoc, rowHeight);
	}

	private void printTextWithoutLineNumbers(JComponent c, Graphics g, PaintContext context,
			Rectangle clip, FieldBackgroundColorManager selectionMap, RowColLocation cursorLoc,
			int rowHeight) {
		int oringalStartX = startX;
		try {
			// strip off the line number padding...
			stripLineNumbersAndLayoutText();
			super.paint(c, g, context, clip, selectionMap, cursorLoc, rowHeight);
		}
		finally {
			// ...restore the line number padding
			reapplyLineNumbersAndLayoutText(oringalStartX);
		}
	}

	private void stripLineNumbersAndLayoutText() {
		startX = startX - lineNumberFieldElement.getStringWidth();
	}

	private void reapplyLineNumbersAndLayoutText(int originalStartX) {
		startX = originalStartX;
	}

	public int getLineNumberWidth() {
		return lineNumberFieldElement.getStringWidth();
	}

	public int getLineNumber() {
		String text = lineNumberFieldElement.getText().trim();
		return Integer.parseInt(text);
	}
}
