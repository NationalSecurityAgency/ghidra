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
package docking.widgets.fieldpanel.listener;
import java.awt.event.MouseEvent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
/**
 * Listener interface for mouse pressed events in the field panel.
 */
public interface FieldMouseListener {
	/**
	 * Called whenever the mouse button is pressed.
	 * @param location the field location of the mouse pointer
	 * @param field the Field object that was clicked on
	 * @param ev the mouse event that generated this call.
	 */
	void buttonPressed(FieldLocation location, Field field, MouseEvent ev);
}
