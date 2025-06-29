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
import java.util.Collection;
import java.util.function.Supplier;

import docking.widgets.fieldpanel.field.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.app.util.XReferenceUtils;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.*;

/**
 * A handler to process {@link XRefFieldMouseHandler} clicks
 */
public class XRefFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES =
		new Class<?>[] { XRefFieldLocation.class, XRefHeaderFieldLocation.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {

		if (mouseEvent.getClickCount() != 2 || mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}

		GoToService goToService = serviceProvider.getService(GoToService.class);
		if (goToService == null) {
			return false;
		}

		// If I double-click on the XRef Header, show references to this place, also works on
		// 'more' field. This is much nicer if you have multiple references to navigate.
		if (isXREFHeaderLocation(location)) {
			showXRefDialog(sourceNavigatable, location, serviceProvider);
			return true;
		}

		Address referencedAddress = getFromReferenceAddress(location);
		boolean isInvisibleXRef = isInvisibleXRef(clickedObject);
		if (isInvisibleXRef) {
			showXRefDialog(sourceNavigatable, location, serviceProvider);
			return true;
		}

		return goTo(sourceNavigatable, referencedAddress, goToService);
	}

	private boolean isInvisibleXRef(Object clickedObject) {

		String clickedText = getText(clickedObject);
		if (XRefFieldFactory.MORE_XREFS_STRING.equals(clickedText)) {
			return true;
		}

		if (clickedObject instanceof StrutFieldElement) {
			// this implies that the xrefs field has been clipped and has used a struct to trigger
			// clipping
			return true;
		}
		return false;
	}

	protected boolean isXREFHeaderLocation(ProgramLocation location) {
		return location instanceof XRefHeaderFieldLocation;
	}

	private String getText(Object clickedObject) {
		if (clickedObject instanceof TextField) {
			TextField textField = (TextField) clickedObject;
			return textField.getText();
		}
		else if (clickedObject instanceof FieldElement) {
			FieldElement fieldElement = (FieldElement) clickedObject;
			return fieldElement.getText();
		}
		return clickedObject.toString();
	}

	protected Address getFromReferenceAddress(ProgramLocation programLocation) {
		return programLocation.getRefAddress();
	}

	protected void showXRefDialog(Navigatable navigatable, ProgramLocation location,
			ServiceProvider serviceProvider) {
		TableService service = serviceProvider.getService(TableService.class);
		if (service == null) {
			return;
		}

		Supplier<Collection<Reference>> refs = () -> XReferenceUtils.getAllXrefs(location);
		XReferenceUtils.showXrefs(navigatable, serviceProvider, service, location, refs);
	}

	private boolean goTo(Navigatable navigatable, Address referencedAddress,
			GoToService goToService) {
		if (referencedAddress != null) {
			return goToService.goTo(navigatable, referencedAddress);
		}
		return false;
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}
}
