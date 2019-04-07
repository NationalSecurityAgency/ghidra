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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigationUtils;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.table.IncomingReferencesTableModel;
import ghidra.util.table.field.OutgoingReferenceEndpoint;

/**
 * A handler to process {@link MnemonicFieldLocation} clicks.
 */
public class MnemonicFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES = new Class[] { MnemonicFieldLocation.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {

		if (mouseEvent.getClickCount() != 2 || mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}

		ProgramManager programManager = serviceProvider.getService(ProgramManager.class);
		if (programManager == null) {
			return false;
		}
		Program program = programManager.getCurrentProgram();
		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitAt(location.getAddress());
		return checkMemReferences(codeUnit, serviceProvider);
	}

	private boolean checkMemReferences(CodeUnit codeUnit, ServiceProvider serviceProvider) {

		if (codeUnit == null) {
			return false;
		}

		Reference[] refs = codeUnit.getMnemonicReferences();
		if (refs.length > 1) {
			List<OutgoingReferenceEndpoint> outgoingReferences = new ArrayList<OutgoingReferenceEndpoint>();
			for (Reference reference : refs) {
				outgoingReferences.add(new OutgoingReferenceEndpoint(reference,
					ReferenceUtils.isOffcut(codeUnit.getProgram(), reference.getToAddress())));
			}

			IncomingReferencesTableModel model =
				new IncomingReferencesTableModel("Mnemonic", serviceProvider,
					codeUnit.getProgram(), outgoingReferences, null);

			TableService service = serviceProvider.getService(TableService.class);
			if (service != null) {
				Navigatable nav = NavigationUtils.getActiveNavigatable();
				service.showTable("Mnemonic", "Mnemonic", model, "References", nav);
				return true;
			}
		}
		else if (refs.length == 1) {
			SymbolTable st = codeUnit.getProgram().getSymbolTable();
			Symbol symbol = st.getSymbol(refs[0]);

			ProgramLocation loc = null;
			if (symbol != null) {
				loc = symbol.getProgramLocation();
			}
			else {
				loc = new AddressFieldLocation(codeUnit.getProgram(), refs[0].getToAddress());
			}

			GoToService goToService = serviceProvider.getService(GoToService.class);
			if (goToService != null) {
				return goToService.goTo(loc);
			}
		}

		return false;
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}
}
