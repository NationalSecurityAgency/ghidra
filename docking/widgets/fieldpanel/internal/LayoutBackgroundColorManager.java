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

import docking.widgets.fieldpanel.support.FieldLocation;

/**
 * Interface for classes that manage the background color of a layout.  The background color is 
 * affected by the current selection and highlight.  Implementers of this class manage the 
 * interaction of the selection and highlight to provide a single object from which to get
 * background color information.
 */
public interface LayoutBackgroundColorManager {

	/**
	 * Returns the overall background color for the entire layout.  If the layout is totally, 
	 * selected, then this color will be the selection color.  If the layout is highlighted,then
	 * the color will be the highlight color.  If both, then the color will be the combined color.
	 * If the color is the same the overall background color of the field panel,
	 * then null will be returned to indicate that the background color for this layout does not
	 * need to be painted. 
	 * @return the background color for this layout or null if it is the same as the background for
	 * the field panel.
	 */
	Color getBackgroundColor();
	
	/**
	 * Returns the color of the padding between fields or null if the color is the same as the
	 * background color for the layout.
	 * @param padIndex the index of the padding area.  0 represents the gap before the first field.
	 * a -1 indicates the gap past the last field.
	 * @return the color for indicated gap padding.
	 */
	Color getPaddingColor(int padIndex);
	
	/**
	 * Returns a {@link FieldBackgroundColorManager} to manage the background colors for field 
	 * indexed by fieldNum.
	 * @param fieldNum the index of the field for which to get a colorManager.
	 * @return the FieldBackgroundColorManager for the given field index.
	 */
	FieldBackgroundColorManager getFieldBackgroundColorManager(int fieldNum);
	
	/**
	 * Returns the background color at a specific location within the layout.
	 * @param location the location in the layout for which to get the background color.
	 * @return the background color at a specific location within the layout.
	 */
	Color getBackgroundColor(FieldLocation location);
}
