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
package docking.widgets.fieldpanel.support;

import java.awt.Rectangle;
import java.awt.event.MouseEvent;

import docking.widgets.fieldpanel.field.Field;

public interface HoverProvider {

	/**
	 * Returns true if this service's popup window is currently visible
	 * @return true if this service's popup window is currently visible
	 */
	public boolean isShowing();

	/**
	 * Hide this service's popup window if visible
	 */
	public void closeHover();

	/**
	 * Notify this service that the mouse is hovering over a specific field within a 
	 * field viewer.
	 * @param fieldLocation the precise mouse location within the field viewer
	 * @param field the field over which the mouse is hovering
	 * @param fieldBounds the rectangle containing the bounds of the given field.
	 * @param event the last mouse motion event over the field viewer component (i.e., FieldPanel).
	 */
	public void mouseHovered(FieldLocation fieldLocation, Field field, Rectangle fieldBounds,
			MouseEvent event);

	/**
	 * If this service's window supports scrolling, scroll by the specified amount.  The value
	 * will be negative when scrolling should move up.
	 * 
	 * @param amount the amount by which to scroll
	 */
	public void scroll(int amount);
}
