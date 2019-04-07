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
import ghidra.program.model.data.Playable;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;

import java.awt.event.MouseEvent;

public class ImageFactoryFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES = new Class[] { ImageFactoryField.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable navigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {
		if (mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}

		if (mouseEvent.getClickCount() == 1) {
			return handleSingleClick(mouseEvent, navigatable, location);
		}

		return false;
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}

	private boolean handleSingleClick(MouseEvent mouseEvent, Navigatable navigatable,
			ProgramLocation location) {

		Program program = navigatable.getProgram();
		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitContaining(location.getAddress());
		if (codeUnit instanceof Data) {
			Data data = (Data) codeUnit;
			Object value = data.getValue();
			if (value instanceof Playable) {
				((Playable) value).clicked(mouseEvent);
				return true;
			}
		}

		return false;
	}
}
