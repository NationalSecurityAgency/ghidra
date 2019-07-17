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
package ghidra.app.services;

import java.awt.event.MouseEvent;

import docking.widgets.fieldpanel.support.FieldLocation;

import ghidra.app.util.viewer.field.ListingField;
import ghidra.program.util.ProgramLocation;

/**
 *
 * Listener that is notified when a mouse button is pressed.
 *
 */
public interface ButtonPressedListener {

	/**
	 * Notification that a mouse button was pressed.
	 * @param location program location when the button was pressed
	 * @param fieldLocation locations within the FieldPanel 
	 * @param field field from the ListingPanel
	 * @param event mouse event for the button pressed
	 */
	public void buttonPressed(ProgramLocation location, 
				FieldLocation fieldLocation, ListingField field, MouseEvent event); 
}
