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
import ghidra.program.util.*;

/**
 * A handler to process {@link CollapsedCodeLocation} mouse clicks.
 */
public class CollapsedCodeFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES = new Class[] {
		CollapsedCodeLocation.class };

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

		if (location instanceof CollapsedCodeLocation loc) {
			Address address = loc.getAddress();
			Function function = program.getListing().getFunctionContaining(address);

			if (function != null) {
				FunctionSignatureFieldLocation gotoLocation =
					new FunctionSignatureFieldLocation(program, function.getEntryPoint());
				goToService.goTo(navigatable, gotoLocation, program);
				return true;
			}
		}
		return false;
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}
}
