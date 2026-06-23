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

import java.awt.event.MouseEvent;

import docking.widgets.fieldpanel.field.FieldElement;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.symtable.SymbolTableService;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.Msg;

/**
 * A handler to process Label field clicks
 */
public class LabelFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES =
		new Class<?>[] { LabelFieldLocation.class, MoreLabelFieldLocation.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {

		if (mouseEvent.getClickCount() != 2 || mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}

		GoToService goToService = serviceProvider.getService(GoToService.class);
		if (goToService == null) {
			Msg.error(this, GoToService.class.getSimpleName() + " not installed!");
			return false;
		}

		SymbolTableService service = serviceProvider.getService(SymbolTableService.class);
		if (service == null) {
			Msg.error(this, SymbolTableService.class.getSimpleName() + " not installed!");
			return false;
		}

		String clickedText = getText(clickedObject);
		if (MoreLabelFieldLocation.MORE_LABELS_STRING.equals(clickedText)) {
			showLabelsDialog(service, location);
			return true;
		}

		if (location instanceof LabelFieldLocation) {
			// Allow double-clicking of any label to show the label dialog.  This allows the user to
			// use the dialog even when the [more] is not showing.
			showLabelsDialog(service, location);
			return true;
		}

		return false;
	}

	private void showLabelsDialog(SymbolTableService service, ProgramLocation location) {

		Address addr = location.getAddress();
		Program program = location.getProgram();
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr);
		service.showSymbols(cu);
	}

	private String getText(Object clickedObject) {
		if (clickedObject instanceof FieldElement) {
			FieldElement fieldElement = (FieldElement) clickedObject;
			return fieldElement.getText();
		}
		return clickedObject.toString();
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}
}
