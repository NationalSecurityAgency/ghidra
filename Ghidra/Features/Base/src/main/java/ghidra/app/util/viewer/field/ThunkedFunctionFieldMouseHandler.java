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

import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;

/**
 * A handler to process {@link OperandFieldLocation} mouse clicks.
 */
public class ThunkedFunctionFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES = new Class[] {
		ThunkedFunctionFieldLocation.class, FunctionNameFieldLocation.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable navigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {

		if (mouseEvent.getClickCount() != 2 || mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}
		
		GoToService goToService = serviceProvider.getService(GoToService.class);
		if (goToService == null) {
			return false;
		}
		
		Program program = location.getProgram();
		
		Address gotoAddr = null;
		if (location instanceof FunctionNameFieldLocation) {
			FunctionNameFieldLocation fieldLocation = (FunctionNameFieldLocation) location;
			
			Function refFunction = program.getFunctionManager().getFunctionAt(
					fieldLocation.getFunctionAddress());
			if (refFunction != null) {
				Function thunkedFunction = refFunction.getThunkedFunction(false);
				if (thunkedFunction != null) {
					gotoAddr = thunkedFunction.getEntryPoint();
				}
			}
		}
		else {
			ThunkedFunctionFieldLocation fieldLocation = (ThunkedFunctionFieldLocation) location;
			gotoAddr = fieldLocation.getRefAddress();
		}
		if (gotoAddr == null) {
			return false;
		}
		if (gotoAddr.isExternalAddress()) {
			// handle navigation to external function
			Symbol externalSym = program.getSymbolTable().getPrimarySymbol(gotoAddr);
			if (externalSym == null) {
				return false;
			}
			ExternalManager externalMgr = program.getExternalManager();
			ExternalLocation extLoc = externalMgr.getExternalLocation(externalSym);
			return goToService.goToExternalLocation(extLoc, false);
		}
		return goToService.goTo(navigatable, gotoAddr);
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}
}
