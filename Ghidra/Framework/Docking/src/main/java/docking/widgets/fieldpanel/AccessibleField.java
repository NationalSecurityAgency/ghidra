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
package docking.widgets.fieldpanel;

import java.awt.*;
import java.awt.event.FocusListener;
import java.text.BreakIterator;
import java.util.Locale;

import javax.accessibility.*;
import javax.swing.JComponent;
import javax.swing.text.AttributeSet;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.RowColLocation;

/**
 * Implements Accessible interfaces for individual fields in the field panel
 */
public class AccessibleField extends AccessibleContext
		implements Accessible, AccessibleComponent, AccessibleText {

	private Field field;
	private int indexInParent;
	private Rectangle boundsInParent;
	private Locale locale;
	private JComponent parent;
	private int caretPos = 0;
	private boolean isSelected = false;

	/**
	 * Constructor
	 * @param field the field this is providing accessible access to
	 * @param parent the component containing the field (FieldPanel)
	 * @param indexInParent the number of this field relative to the visible fields on the screen.
	 * @param bounds the bounds of the field relative to the field panel.
	 */
	public AccessibleField(Field field, JComponent parent, int indexInParent, Rectangle bounds) {
		this.field = field;
		this.parent = parent;
		this.indexInParent = indexInParent;
		this.locale = parent.getLocale();
		this.boundsInParent = bounds;
		setAccessibleName("Field");
	}

	/**
	 * Sets the position of the cursor relative to the text in this field. It is only meaningful
	 * when the corresponding field is the field containing the field panel's actual cursor.
	 * @param caretPos the offset into the text of the field of where the cursor is being displayed
	 * by the field panel.
	 */
	public void setCaretPos(int caretPos) {
		if (caretPos >= 0 && caretPos < field.getText().length()) {
			this.caretPos = caretPos;
		}
	}

	/**
	 * Sets that this field is part of the overall selection.
	 * @param selected true if the field is part of the selection; false otherwise
	 */
	public void setSelected(boolean selected) {
		this.isSelected = selected;
	}

	/**
	 * Returns true if the field is currently part of a selection.
	 * @return true if the field is currently part of a selection.
	 */
	public boolean isSelected() {
		return isSelected;
	}

	/**
	 * Returns the text of the field
	 * @return the text of the field
	 */
	public String getText() {
		return field.getText();
	}

	/**
	 * Converts a row,col position to an text offset in the field
	 * @param row the row
	 * @param col the col
	 * @return an offset into the text that represents the row,col position
	 */
	public int getTextOffset(int row, int col) {
		return field.screenLocationToTextOffset(row, col);
	}

	/**
	 * Returns the field associated with this AccessibleField.
	 * @return the field associated with this AccessibleField
	 */
	public Field getField() {
		return field;
	}

//==================================================================================================
// Accessible methods
//==================================================================================================

	@Override
	public AccessibleContext getAccessibleContext() {
		return this;
	}

//==================================================================================================
// AccessibleContext methods
//==================================================================================================

	@Override
	public AccessibleText getAccessibleText() {
		return this;
	}

	@Override
	public AccessibleComponent getAccessibleComponent() {
		return this;
	}

	@Override
	public AccessibleRole getAccessibleRole() {
		return AccessibleRole.TEXT;
	}

	@Override
	public AccessibleStateSet getAccessibleStateSet() {
		AccessibleStateSet states = new AccessibleStateSet();
		states.add(AccessibleState.MULTI_LINE);
		states.add(AccessibleState.TRANSIENT);
		return states;
	}

	@Override
	public int getAccessibleIndexInParent() {
		return indexInParent;
	}

	@Override
	public int getAccessibleChildrenCount() {
		return 0;
	}

	@Override
	public Accessible getAccessibleChild(int i) {
		return null;
	}

	@Override
	public Locale getLocale() throws IllegalComponentStateException {
		return locale;
	}

//==================================================================================================
// AccessibleText methods
//==================================================================================================

	@Override
	public int getIndexAtPoint(Point p) {
		// fields are weird, internally their 0 y position is the font baseline, so we
		// need to compensate for that to find the row. Also, fields internal x position
		// is relative to the field panel and the p being given here is relative to the field,
		// we need to add the fields startingX to the given point.
		int row = field.getRow(p.y - field.getHeightAbove());
		int col = field.getCol(row, p.x + field.getStartX());
		int result = field.screenLocationToTextOffset(row, col);
		return result;
	}

	@Override
	public Rectangle getCharacterBounds(int i) {
		if (i < 0 || i >= getCharCount()) {
			return new Rectangle(0, 0, 0, 0);
		}
		RowColLocation rowCol = field.textOffsetToScreenLocation(i);
		int row = rowCol.row();
		int col = rowCol.col();
		Rectangle charBounds = field.getCursorBounds(row, col);
		Rectangle nextCharBounds = field.getCursorBounds(row, col + 1);

		charBounds.width = nextCharBounds.x - charBounds.x;
		// again the bounds give are relative to the layout and field panel and this method wants
		// a bounds relative to the field.
		charBounds.y += field.getHeightAbove();
		charBounds.x -= field.getStartX();
		return charBounds;
	}

	@Override
	public int getCharCount() {
		return field.getText().length();
	}

	@Override
	public String getAtIndex(int part, int index) {
		String text = field.getText();
		if (index < 0 || index >= text.length()) {
			return null;
		}

		switch (part) {
			case AccessibleText.CHARACTER:
				return text.substring(index, index + 1);
			case AccessibleText.WORD:
				BreakIterator words = BreakIterator.getWordInstance(locale);
				words.setText(text);
				int end = words.following(index);
				return text.substring(words.previous(), end);
			case AccessibleText.SENTENCE:
				BreakIterator sentences = BreakIterator.getSentenceInstance(locale);
				sentences.setText(text);
				end = sentences.following(index);
				return text.substring(sentences.previous(), end);
			default:
				return null;
		}

	}

	@Override
	public String getAfterIndex(int part, int index) {
		String text = field.getText();
		if (index < 0 || index >= text.length() - 1) {
			return null;
		}

		switch (part) {
			case AccessibleText.CHARACTER:
				return text.substring(index + 1, index + 2);
			case AccessibleText.WORD:
				BreakIterator words = BreakIterator.getWordInstance(locale);
				words.setText(text);
				int start = words.following(index);
				if (start == BreakIterator.DONE || start >= text.length()) {
					return null;
				}
				int end = words.following(start);
				if (end == BreakIterator.DONE || end > text.length()) {
					return null;
				}
				return text.substring(start, end);
			case AccessibleText.SENTENCE:
				BreakIterator sentences = BreakIterator.getSentenceInstance(locale);
				sentences.setText(text);
				start = sentences.following(index);
				if (start == BreakIterator.DONE || start > text.length()) {
					return null;
				}
				end = sentences.following(start);
				if (end == BreakIterator.DONE || end > text.length()) {
					return null;
				}
				return text.substring(start, end);
			default:
				return null;
		}
	}

	@Override
	public String getBeforeIndex(int part, int index) {
		String text = field.getText();
		if (index < 1 || index > text.length()) {
			return null;
		}

		switch (part) {
			case AccessibleText.CHARACTER:
				return text.substring(index - 1, index);
			case AccessibleText.WORD:
				BreakIterator words = BreakIterator.getWordInstance(locale);
				words.setText(text);

				// move to the beginning of the current word so the algorithm
				// gives us the previous word and not the word we are on. Note: this is needed
				// because the preceding() method behaves differently if in the middle of a
				// word than if at the beginning of the word.
				if (!words.isBoundary(index)) {
					words.preceding(index);
				}
				int start = words.previous();
				int end = words.next();
				if (start == BreakIterator.DONE) {
					return null;
				}
				return text.substring(start, end);
			case AccessibleText.SENTENCE:
				BreakIterator sentences = BreakIterator.getSentenceInstance(locale);
				sentences.setText(text);
				if (!sentences.isBoundary(index)) {
					sentences.preceding(index);
				}
				start = sentences.previous();
				end = sentences.next();
				if (start == BreakIterator.DONE) {
					return null;
				}
				return text.substring(start, end);
			default:
				return null;
		}
	}

	@Override
	public int getCaretPosition() {
		return caretPos;
	}

	@Override
	public AttributeSet getCharacterAttribute(int i) {
		return null;
	}

	@Override
	public int getSelectionStart() {
		// field selection is all or nothing so this always returns 0
		return 0;
	}

	@Override
	public int getSelectionEnd() {
		// field selection is all or nothing, so if selected this will return the end of the text
		// otherwise, return 0 because if selectionStart == selectionEnd means no selection
		if (isSelected) {
			return field.getText().length();
		}
		return 0;
	}

	@Override
	public String getSelectedText() {
		// selection is all or nothing
		if (isSelected) {
			return field.getText();
		}
		return null;
	}

//==================================================================================================
// AccessibleComponent methods
//==================================================================================================

	@Override
	public Color getBackground() {
		return parent.getBackground();
	}

	@Override
	public void setBackground(Color c) {
		// unsupported
	}

	@Override
	public Color getForeground() {
		return parent.getForeground();
	}

	@Override
	public void setForeground(Color c) {
		// unsupported
	}

	@Override
	public Cursor getCursor() {
		return parent.getCursor();
	}

	@Override
	public void setCursor(Cursor cursor) {
		// unsupported
	}

	@Override
	public Font getFont() {
		return parent.getFont();
	}

	@Override
	public void setFont(Font f) {
		// unsupported
	}

	@Override
	public FontMetrics getFontMetrics(Font f) {
		return parent.getFontMetrics(f);
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public void setEnabled(boolean b) {
		// unsupported
	}

	@Override
	public boolean isVisible() {
		return true;
	}

	@Override
	public void setVisible(boolean b) {
		// unsupported
	}

	@Override
	public boolean isShowing() {
		return true;
	}

	@Override
	public boolean contains(Point p) {
		return (p.x >= 0) && (p.x < field.getWidth()) && (p.y >= 0) && (p.y < field.getHeight());
	}

	@Override
	public Point getLocationOnScreen() {
		Point parentLoc = parent.getLocationOnScreen();
		return new Point(parentLoc.x + boundsInParent.x, parentLoc.y + boundsInParent.y);
	}

	@Override
	public Point getLocation() {
		return boundsInParent.getLocation();
	}

	@Override
	public void setLocation(Point p) {
		// unsupported
	}

	@Override
	public Rectangle getBounds() {
		return new Rectangle(boundsInParent);
	}

	@Override
	public void setBounds(Rectangle r) {
		// unsupported
	}

	@Override
	public Dimension getSize() {
		return new Dimension(field.getWidth(), field.getHeight());
	}

	@Override
	public void setSize(Dimension d) {
		// unsupported
	}

	@Override
	public Accessible getAccessibleAt(Point p) {
		return null;
	}

	@Override
	public boolean isFocusTraversable() {
		return false;
	}

	@Override
	public void requestFocus() {
		// unsupported
	}

	@Override
	public void addFocusListener(FocusListener l) {
		// unsupported
	}

	@Override
	public void removeFocusListener(FocusListener l) {
		// unsupported
	}

}
