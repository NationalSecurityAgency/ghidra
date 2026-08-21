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
package ghidra.app.merge.structures;

/**
 * Base class for items that can be displayed in a {@link CoordinatedStructureDisplay}. These are
 * basically different views from a {@link CoordinatedStructureLine} where each coordinated line
 * has three comparison items, one for the left side structure, one for the right side structure,
 * and for the merged structure.
 */
public abstract class ComparisonItem implements Comparable<ComparisonItem> {
	// the max number of display columns any ComparisonItem can have
	public static int MAX_COLS = 5;

	enum ItemApplyState {
		NON_APPLIALBLE, APPLIED, NOT_APPLIED
	}

	private int line;
	private String type;

	/**
	 * Constructor
	 * @param type The type of comparison item (name, comment, component, etc.)
	 * @param line the line number in the overall coordinated structure model
	 */
	ComparisonItem(String type, int line) {
		this.type = type;
		this.line = line;
	}

	/**
	 * Returns the text to be display for the given column index.
	 * @param column the index of the column to get text for
	 * @return the text to be display for the given column index.
	 */
	public String getColumnText(int column) {
		return "";
	}

	/**
	 * Returns true if this items represents something that can be applied or not applied. Used
	 * to determine if a button should be created for this item.  For
	 * example, a structure name can applied from either side, but the simple syntax line "{"
	 * is the same for all sides, so it is never appliable and should not have a corresponding
	 * button.
	 * @return true if this item can potentially be applied.
	 */
	public boolean isAppliable() {
		return false;
	}

	/**
	 * Returns true if any information in this item is not currently applied to the merged item.
	 * if true, the button should be displayed as unselected, indicating to the user that this
	 * item has information that can be applied.
	 * @return true if any information in this item can be applied.
	 */
	public boolean canApplyAny() {
		return false;
	}

	/**
	 * Returns true if the information from this item can be cleared. Currently only items
	 * from component lines can be cleared. Items such as the structure name can never be cleared
	 * and can only change by selecting the other side value.
	 * If true, the button will be allowed to become unselected without the other side being
	 * selected.
	 * @return true if the information from this item can be cleared
	 */
	public boolean canClear() {
		return false;
	}

	/**
	 * Returns true if the specific information represented by the given column index is applied.
	 * This is used by the renderer to bold information that is applied and fade information
	 * that is not applied.
	 * @param column the column index to check if it is applied
	 * @return  true if this column information is currently applied
	 */
	public boolean isApplied(int column) {
		return false;
	}

	/**
	 * Returns true if the specific information represented by the given column index is something
	 * can be applied whether or not it is currently applied. This is used by the renderer to
	 * render this columns test normally (not faded or bold)
	 * @param column the column index to check if it is appliable
	 * @return  true if this columns information is changeable
	 */
	public boolean isAppliable(int column) {
		return false;
	}

	/**
	 * Returns the minimum width of this column. Used to reserve space for a column even when
	 * there is no text to display in the column. The column may be wider if its text is wider
	 * than the minimum width. Used to help the renderer allocate available extra space when
	 * the view is resized.
	 * @param column the column to get the min width for
	 * @return the minimum width of this column
	 */
	public int getMinWidth(int column) {
		return 0;
	}

	/**
	 * Specifies if the column text should be left or right justified within it column.
	 * @param column the column index
	 * @return true if the column text should be justified to the left side of the column
	 */
	public boolean isLeftJustified(int column) {
		return true;
	}

	/**
	 * Applies all the information in this item to the merged structure.
	 */
	public void applyAll() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Clears this item from the merged structure. Normally items from one side or the other
	 * are cleared when the corresponding item for the other side is applied. This allows the
	 * state where neither side is applied.
	 */
	public void clear() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns if this item represent a blank line. Useful for removing blank lines from the
	 * merge structure view.
	 * @return true if this item represents a blank line
	 */
	public boolean isBlank() {
		return false;
	}

	/**
	 * Return the line number for this item in the coordinated display. Note that this may
	 * be different from its index in its list model. The merged display removes blank lines, but
	 * maintains the line number where it matches in the left/right displays. This is uses to
	 * coordinated the left/right/merged views.
	 * @return the line number for this item
	 */
	public int getLine() {
		return line;
	}

	/**
	 * Returns the type for this item. Used to align the columns of like items. For example,
	 * all the fields in the component lines must line up, but that alignment is not coordinated
	 * with other categories such as the structure name line.
	 * @return the category for this item.
	 */
	protected String getType() {
		return type;
	}

	@Override
	public int compareTo(ComparisonItem o) {
		return line - o.line;
	}
}
