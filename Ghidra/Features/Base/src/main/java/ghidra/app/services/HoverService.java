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
package ghidra.app.services;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * <code>HoverService</code> provides the ability to popup data Windows over a Field viewer
 * in response to the mouse hovering over a single Field.
 */
public interface HoverService {

	/**
	 * Returns the priority of this hover service.   A lower priority is more important.
	 * @return the priority
	 */
	public int getPriority();

	/**
	 * If this service's window supports scrolling, scroll by the specified amount.
	 * @param amount the amount to scroll
	 */
	public void scroll(int amount);

	/**
	 * Return whether hover mode is "on"
	 * @return the priority
	 */
	public boolean hoverModeSelected();

	/**
	 * Returns a component to be shown in a popup window that is relevant to the given parameters.
	 * Null is returned if there is no appropriate information to display.
	 * @param program the program that is being hovered over.
	 * @param programLocation the program location where the mouse is hovering.
	 * @param fieldLocation the precise mouse location within the field viewer
	 * @param field the field over which the mouse is hovering
	 * @return The component to be shown for the given location information.
	 */
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field);

	/**
	 * Provides notification when this hover component is popped-down
	 */
	public void componentHidden();

	/**
	 * Provides notification when this hover component is popped-up
	 */
	public void componentShown();

}
