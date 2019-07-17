/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.widgets.fieldpanel.internal;

import java.awt.Color;
import java.util.List;

import docking.widgets.fieldpanel.support.Highlight;

/**
 * Interface for classes that manage the background color of fields.  The background color is 
 * affected by the current selection and highlight.  Implementers of this class manage the 
 * interaction of the selection and highlight to provide a single object from which to get
 * background color information.
 */
public interface FieldBackgroundColorManager {
	/**
	 * Returns the overall background color for the entire field.  If the field is totally, 
	 * selected, then this color will be the selection color.  If the field is highlighted,then
	 * the color will be the highlight color.  If both, then the color will be the combined color.
	 * If the color is the same the overall background color of the layout containing this field,
	 * then null will be returned to indicate that the background color for this field does not
	 * need to be painted 
	 * @return the background color for this field or null if it is the same as the background for
	 * the entire layout.
	 */
	Color getBackgroundColor();
	
	/**
	 * Return a list of highlights (background colors ranges) for a given row of text in the field. 
	 * @param row the row for which to get a list of highlights.
	 * @return a list of highlights for the row.
	 */
	List<Highlight> getSelectionHighlights(int row);
	
	/**
	 * Returns the color for the right or left padding within the field.  The padding is difference
	 * of the width of the field and the width of the text being displayed.  Most fields pad
	 * to the right, but a few pad to the left.
	 * @param padIndex either 0 or 1 to get left padding or right padding respectively.
	 * @return the color for either the right or left padding.
	 */
	Color getPaddingColor(int padIndex);
}
