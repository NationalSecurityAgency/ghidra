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

import static javax.accessibility.AccessibleContext.*;

import java.awt.Point;
import java.awt.Rectangle;
import java.math.BigInteger;
import java.util.*;

import javax.accessibility.*;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.*;

/**
 * Contains all the code for implementing the AccessibleFieldPanel which is an inner class in
 * the FieldPanel class. The AccessibleFieldPanel has to be declared as an inner class because
 * it needs to extends AccessibleJComponent which is a non-static inner class of JComponent. 
 * However, we did not want to put all the logic in there as FieldPanel is already an
 * extremely large and complex class. Also, by delegating the the logic, testing is much
 * easier.
 * <P>
 * The model for accessibility for the FieldPanel is a bit complex because
 * the field panel displays text, but in a 2 dimensional array of fields, where each field
 * has potentially 2 dimensional text.  So for the purpose of accessibility, the FieldPanel 
 * acts as both a text field and a text component.
 * <P>
 * To support screen readers reacting to cursor movements in the FieldPanel, the FieldPanel
 * acts like a text field, but it acts like it only has the text of one inner Field at a time
 * (The one where the cursor is). The other approach that was considered was to treat the field
 * panel as a single text document. This would be difficult to implement because of the way fields
 * are multi-lined. Also, the user of the screen reader would lose all concepts that there are
 * fields. By maintaining the fields as a concept to the screen reader, it can provide more
 * meaningful descriptions as the cursor is moved between fields. 
 * <P>
 * The Field panel also acts as an {@link AccessibleComponent} with virtual children for each of its 
 * visible fields. This is what allows screen readers to read the context of whatever the mouse
 * is hovering over keeping the data separated by the field boundaries.
 */
public class AccessibleFieldPanelDelegate {
	private List<AccessibleLayout> accessibleLayouts;
	private int totalFieldCount;
	private AccessibleField[] fieldsCache;
	private FieldPanel panel;

	// caret position tracking
	private FieldLocation cursorLoc;
	private int caretPos;
	private AccessibleField cursorField;

	private FieldDescriptionProvider fieldDescriber = (l, f) -> "";
	private AccessibleContext context;
	private String description;
	private FieldSelection currentSelection;

	public AccessibleFieldPanelDelegate(List<AnchoredLayout> layouts, AccessibleContext context,
			FieldPanel panel) {
		this.context = context;
		this.panel = panel;
		setLayouts(layouts);
	}

	/**
	 * Whenever the set of visible layouts changes, the field panel rebuilds its info for the
	 * new visible fields and notifies the accessibility system that its children changed.
	 * @param layouts the new set of visible layouts.
	 */
	public void setLayouts(List<AnchoredLayout> layouts) {
		totalFieldCount = 0;
		cursorField = null;
		accessibleLayouts = new ArrayList<>(layouts.size());
		for (AnchoredLayout layout : layouts) {
			AccessibleLayout accessibleLayout = new AccessibleLayout(layout, totalFieldCount);
			accessibleLayouts.add(accessibleLayout);
			totalFieldCount += layout.getNumFields();
		}
		fieldsCache = new AccessibleField[totalFieldCount];
		context.firePropertyChange(ACCESSIBLE_INVALIDATE_CHILDREN, null, panel);
		if (cursorLoc != null) {
			setCaret(cursorLoc, EventTrigger.GUI_ACTION);
		}
	}

	/**
	 * Tells this delegate that the cursor moved. It updates its internal state and fires
	 * events to the accessibility system.
	 * @param newCursorLoc the new FieldLoation of the cursor
	 * @param trigger the event trigger
	 */
	public void setCaret(FieldLocation newCursorLoc, EventTrigger trigger) {
		if (cursorField == null || !isSameField(cursorLoc, newCursorLoc)) {
			AccessibleTextSequence oldSequence = getAccessibleTextSequence(cursorField);
			cursorLoc = newCursorLoc;
			cursorField = getAccessibleField(newCursorLoc);
			AccessibleTextSequence newSequence = getAccessibleTextSequence(cursorField);
			String oldDescription = description;
			description = generateDescription();

			if (trigger == EventTrigger.GUI_ACTION) {
				context.firePropertyChange(ACCESSIBLE_TEXT_PROPERTY, oldSequence, newSequence);
				context.firePropertyChange(ACCESSIBLE_DESCRIPTION_PROPERTY, oldDescription,
					description);
			}
			if (currentSelection != null && currentSelection.contains(cursorLoc)) {
				updateCurrentFieldSelectedState(trigger);
			}
			caretPos = -1;
		}
		if (cursorField == null) {
			caretPos = 0;
			return;
		}
		int newCaretPos = cursorField.getTextOffset(newCursorLoc.getRow(), newCursorLoc.getCol());
		cursorField.setCaretPos(newCaretPos);
		if (newCaretPos != caretPos && trigger == EventTrigger.GUI_ACTION) {
			context.firePropertyChange(ACCESSIBLE_CARET_PROPERTY, caretPos, newCaretPos);
		}
		caretPos = newCaretPos;
		cursorLoc = newCursorLoc;
	}

	/**
	 * Tells this delegate that the selection has changed. If the current field is in the selection,
	 * it sets the current AccessibleField to be selected. (A field is either entirely selected
	 * or not)
	 * @param currentSelection the new current field panel selection
	 * @param trigger the event trigger
	 */
	public void setSelection(FieldSelection currentSelection, EventTrigger trigger) {
		this.currentSelection = currentSelection;
		updateCurrentFieldSelectedState(trigger);
	}

	private void updateCurrentFieldSelectedState(EventTrigger trigger) {
		if (cursorField == null) {
			return;
		}
		boolean oldIsSelected = cursorField.isSelected();
		boolean newIsSelected = currentSelection != null && currentSelection.contains(cursorLoc);
		cursorField.setSelected(newIsSelected);
		if (oldIsSelected != newIsSelected && trigger == EventTrigger.GUI_ACTION) {
			context.firePropertyChange(ACCESSIBLE_SELECTION_PROPERTY, null, null);
		}
	}

	private String generateDescription() {
		Field field = cursorField != null ? cursorField.getField() : null;
		return fieldDescriber.getDescription(cursorLoc, field);
	}

	private AccessibleTextSequence getAccessibleTextSequence(AccessibleField field) {
		if (field == null) {
			return new AccessibleTextSequence(0, 0, "");
		}
		String text = field.getField().getText();
		return new AccessibleTextSequence(0, text.length(), text);
	}

	/**
	 * Returns the caret position relative the current active field.
	 * @return  the caret position relative the current active field
	 */
	public int getCaretPosition() {
		return caretPos;
	}

	/**
	 * Returns the number of characters in the current active field.
	 * @return the number of characters in the current active field.
	 */
	public int getCharCount() {
		return cursorField != null ? cursorField.getCharCount() : 0;
	}

	private boolean isSameField(FieldLocation loc1, FieldLocation loc2) {
		if (loc1.getIndex() != loc2.getIndex()) {
			return false;
		}
		return loc1.getFieldNum() == loc2.getFieldNum();
	}

	/**
	 * Returns the n'th AccessibleField that is visible on the screen.
	 * @param fieldNum the number of the field to get
	 * @return the n'th AccessibleField that is visible on the screen
	 */
	public AccessibleField getAccessibleField(int fieldNum) {
		if (fieldNum < 0 || fieldNum >= fieldsCache.length) {
			return null;
		}
		if (fieldsCache[fieldNum] == null) {
			fieldsCache[fieldNum] = createAccessibleField(fieldNum);
		}
		return fieldsCache[fieldNum];
	}

	/**
	 * Returns the AccessibleField associated with the given field location.
	 * @param loc the FieldLocation to get the visible field for
	 * @return the AccessibleField associated with the given field location
	 */
	public AccessibleField getAccessibleField(FieldLocation loc) {
		AccessibleLayout accessibleLayout = getAccessibleLayout(loc.getIndex());
		if (accessibleLayout != null) {
			return getAccessibleField(accessibleLayout.getStartingFieldNum() + loc.getFieldNum());
		}

		LayoutModel layoutModel = panel.getLayoutModel();
		Layout layout = layoutModel.getLayout(loc.getIndex());
		if (layout == null) {
			return null;
		}
		Field field = layout.getField(loc.getFieldNum());
		return new AccessibleField(field, panel, loc.getFieldNum(), null);
	}

	private AccessibleLayout getAccessibleLayout(BigInteger index) {
		if (accessibleLayouts == null) {
			return null;
		}
		int result = Collections.binarySearch(accessibleLayouts, index,
			Comparator.comparing(
				o -> o instanceof AccessibleLayout lh ? lh.getIndex() : (BigInteger) o,
				BigInteger::compareTo));

		if (result < 0) {
			return null;
		}
		return accessibleLayouts.get(result);
	}

	private AccessibleField createAccessibleField(int fieldNum) {
		int result = Collections.binarySearch(accessibleLayouts, fieldNum, Comparator.comparingInt(
			o -> o instanceof AccessibleLayout lh ? lh.getStartingFieldNum() : (Integer) o));
		if (result < 0) {
			result = -result - 2;
		}
		AccessibleLayout layout = accessibleLayouts.get(result);
		return layout.createAccessibleField(fieldNum);
	}

	/**
	 * Return the bounds relative to the field panel for the character at the given index
	 * @param index the index of the character in the active field whose bounds is to be returned.
	 * @return the bounds relative to the field panel for the character at the given index
	 */
	public Rectangle getCharacterBounds(int index) {
		if (cursorField == null) {
			return null;
		}
		Point loc = cursorField.getLocation();
		Rectangle bounds = cursorField.getCharacterBounds(index);
		bounds.x += loc.x;
		bounds.y += loc.y;
		return bounds;
	}

	/**
	 * Returns the character index at the given point relative to the FieldPanel. Note this
	 * only returns chars in the active field.
	 * @param p the point to get the character for
	 * @return the character index at the given point relative to the FieldPanel.
	 */
	public int getIndexAtPoint(Point p) {
		if (cursorField == null) {
			return 0;
		}
		Rectangle bounds = cursorField.getBounds();
		if (!bounds.contains(p)) {
			return -1;
		}
		Point localPoint = new Point(p.x - bounds.x, p.y - bounds.y);
		return cursorField.getIndexAtPoint(localPoint);
	}

	/**
	 * Returns the char, word, or sentence at the given char index.
	 * @param part specifies char, word or sentence (See {@link AccessibleText})
	 * @param index the character index to get data for
	 * @return the char, word, or sentences at the given char index
	 */
	public String getAtIndex(int part, int index) {
		if (cursorField == null) {
			return "";
		}
		return cursorField.getAtIndex(part, index);
	}

	/**
	 * Returns the char, word, or sentence after the given char index.
	 * @param part specifies char, word or sentence (See {@link AccessibleText})
	 * @param index the character index to get data for
	 * @return the char, word, or sentence after the given char index
	 */
	public String getAfterIndex(int part, int index) {
		if (cursorField == null) {
			return "";
		}
		return cursorField.getAfterIndex(part, index);
	}

	/**
	 * Returns the char, word, or sentence at the given char index.
	 * @param part specifies char, word or sentence (See {@link AccessibleText})
	 * @param index the character index to get data for
	 * @return the char, word, or sentence at the given char index
	 */
	public String getBeforeIndex(int part, int index) {
		if (cursorField == null) {
			return "";
		}
		return cursorField.getBeforeIndex(part, index);
	}

	/**
	 * Returns the number of visible field showing on the screen in the field panel.
	 * @return the number of visible field showing on the screen in the field panel
	 */
	public int getFieldCount() {
		return totalFieldCount;
	}

	/**
	 * Returns the {@link AccessibleField} that is at the given point relative to the FieldPanel.
	 * @param p the point to get an Accessble child at
	 * @return the {@link AccessibleField} that is at the given point relative to the FieldPanel
	 */
	public Accessible getAccessibleAt(Point p) {
		int result = Collections.binarySearch(accessibleLayouts, p.y, Comparator
				.comparingInt(o -> o instanceof AccessibleLayout lh ? lh.getYpos() : (Integer) o));

		if (result < 0) {
			result = -result - 2;
		}
		if (result < 0 || result >= accessibleLayouts.size()) {
			return null;
		}
		int fieldNum = accessibleLayouts.get(result).getFieldNum(p);
		return getAccessibleField(fieldNum);
	}

	/**
	 * Returns a description of the current field
	 * @return a description of the current field
	 */
	public String getFieldDescription() {
		return description;
	}

	/**
	 * Sets the {@link FieldDescriptionProvider} that can generate descriptions of the current
	 * field.
	 * @param provider the description provider 
	 */
	public void setFieldDescriptionProvider(FieldDescriptionProvider provider) {
		fieldDescriber = provider;
	}

	/**
	 * Returns the selection character start index. This currently always returns 0 as
	 * selections are all or nothing.
	 * @return the selection character start index.
	 */
	public int getSelectionStart() {
		if (cursorField == null) {
			return 0;
		}
		return cursorField.getSelectionStart();
	}

	/**
	 * Returns the selection character end index. This is either 0, indicating there is no selection
	 * or the index at the end of the text meaning the entire field is selected.
	 * @return the selection character start index.
	 */
	public int getSelectionEnd() {
		if (cursorField == null) {
			return 0;
		}
		return cursorField.getSelectionEnd();
	}

	/**
	 * Returns either null if the field is not selected or the full field text if it is selected.
	 * @return either null if the field is not selected or the full field text if it is selected
	 */
	public String getSelectedText() {
		if (cursorField == null) {
			return null;
		}
		return cursorField.getSelectedText();

	}

	/**
	 * Wraps each AnchoredLayout to assist organizing the list of layouts into a single list
	 * of fields.
	 */
	private class AccessibleLayout {

		private AnchoredLayout layout;
		private int startingFieldNum;

		public AccessibleLayout(AnchoredLayout layout, int startingFieldNum) {
			this.layout = layout;
			this.startingFieldNum = startingFieldNum;
		}

		/**
		 * Creates the AccessibleField as needed.
		 * @param fieldNum the number of the field to create an AccessibleField for. This number
		 * is relative to all the fields in the field panel and not to this layout.
		 * @return an AccessibleField for the given fieldNum
		 */
		public AccessibleField createAccessibleField(int fieldNum) {
			int fieldNumInLayout = fieldNum - startingFieldNum;
			Field field = layout.getField(fieldNumInLayout);
			Rectangle fieldBounds = layout.getFieldBounds(fieldNumInLayout);
			return new AccessibleField(field, panel, fieldNum, fieldBounds);
		}

		/**
		 * Returns the overall field number of the first field in this layout. For example, 
		 * the first layout would have a starting field number of 0 and if it has 5 fields, the
		 * next layout would have a starting field number of 5 and so on.
		 * @return the overall field number of the first field in this layout.
		 */
		public int getStartingFieldNum() {
			return startingFieldNum;
		}

		/**
		 * Returns the overall field number of the field containing the given point.
		 * @param p the point to find the field for
		 * @return the overall field number of the field containing the given point.
		 */
		public int getFieldNum(Point p) {
			return layout.getFieldIndex(p.x, p.y) + startingFieldNum;
		}

		/**
		 * Return the y position of this layout relative to the field panel.
		 * @return the y position of this layout relative to the field panel.
		 */
		public int getYpos() {
			return layout.getYPos();
		}

		/**
		 * Returns the index of the layout as defined by the client code. The only requirements for
		 * indexes is that the index for a layout is always bigger then the index of the previous
		 * layout.
		 * @return the index of the layout as defined by the client code.
		 */
		public BigInteger getIndex() {
			return layout.getIndex();
		}
	}
}
