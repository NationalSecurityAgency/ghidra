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
import ghidra.app.util.viewer.format.ErrorListingField;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

import java.awt.event.MouseEvent;

/**
 * A handler to process {@link ErrorListingField} clicks.
 */
public class ErrorFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES = new Class[] { ErrorListingField.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {

		if (mouseEvent.getClickCount() != 2 || mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}
		ErrorListingField errorField = (ErrorListingField) clickedObject;
		String fieldName = errorField.getFieldFactory().getFieldName();
		Msg.showError(this, null, "Listing Field Exception", "Exception occurred while rendering '" +
			fieldName + "' field", errorField.getThrowable());
		return true;
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}

}
