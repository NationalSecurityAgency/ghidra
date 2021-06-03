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
package ghidra.app.util.viewer.field;

import ghidra.app.nav.Navigatable;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.util.ProgramLocation;

import java.awt.event.MouseEvent;

import docking.widgets.fieldpanel.field.Field;

public interface FieldMouseHandler {
	/**
	 * Called when a field {@link Field} has been clicked.  The object being passed in may be
	 * of any type, as returned by the clicked field.  The type is guaranteed to be one of the
	 * types returned in the call to {@link #getSupportedProgramLocations()}.
	 * 
	 * @param clickedObject The object that was clicked
	 * @param sourceNavigatable The source navigatable that was clicked upon.
	 * @param programLocation The location at the time the click was made. Due to swing delay, this
	 * location may not be the same as you would get if you asked the navagatable for the current
	 * location.SC
	 * @param mouseEvent The mouse event that triggered the click
	 * @param serviceProvider A service provider used to access system resources.
	 * @return true if this handler wishes to have exclusive handling rights to processing the
	 *         <code>clickedObject</code>
	 * @see   ListingField#getClickedObject(ghidra.util.bean.field.FieldLocation)
	 */
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation programLocation, MouseEvent mouseEvent, ServiceProvider serviceProvider);

	/**
	 * Returns an array of types that this handler wishes to handle.
	 * 
	 * @return an array of types that this handler wishes to handle.
	 */
	public Class<?>[] getSupportedProgramLocations();

}
