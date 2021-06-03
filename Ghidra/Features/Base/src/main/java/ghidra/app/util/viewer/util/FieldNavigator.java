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
package ghidra.app.util.viewer.util;

import java.awt.event.MouseEvent;
import java.util.*;

import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.util.viewer.field.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.util.ProgramLocation;
import ghidra.util.classfinder.ClassSearcher;

/**
 * Helper class to navigate to an address when user double clicks in a 
 * Field.  This class will find {@link FieldMouseHandlerExtension}s by using the {@link ClassSearcher}.
 */
public class FieldNavigator implements ButtonPressedListener, FieldMouseHandlerService {
	private Map<Class<?>, List<FieldMouseHandler>> fieldMouseHandlers;
	private ServiceProvider serviceProvider;
	private final Navigatable navigatable;

	public FieldNavigator(ServiceProvider serviceProvider, Navigatable navigatable) {
		this.serviceProvider = serviceProvider;
		if (navigatable == null) {
			GoToService service = serviceProvider.getService(GoToService.class);
			if (service != null) {
				navigatable = service.getDefaultNavigatable();
			}
		}
		this.navigatable = navigatable;

	}

	private void fieldElementClicked(Object clickedObject, ProgramLocation programLocation,
			MouseEvent mouseEvent) {

		// look for handlers registered on the clicked object
		List<FieldMouseHandler> handlerList =
			getFieldMouseHandlersForLocation(clickedObject.getClass());
		if (processHandlerList(handlerList, clickedObject, programLocation, mouseEvent)) {
			return;
		}

		// next look for handlers registered on the program location
		handlerList = getFieldMouseHandlersForLocation(programLocation.getClass());
		processHandlerList(handlerList, clickedObject, programLocation, mouseEvent);
	}

	private boolean processHandlerList(List<FieldMouseHandler> handlerList, Object clickedObject,
			ProgramLocation programLocation, MouseEvent mouseEvent) {
		if (handlerList != null) {
			for (Object element : handlerList) {
				FieldMouseHandler handler = (FieldMouseHandler) element;
				if (handler.fieldElementClicked(clickedObject, navigatable, programLocation,
					mouseEvent, serviceProvider)) {
					return true;
				}
			}
		}
		return false;
	}

	// loads all FieldMouseHandler implementations
	private Map<Class<?>, List<FieldMouseHandler>> initializeFieldMouseHandlers() {
		Map<Class<?>, List<FieldMouseHandler>> map =
			new HashMap<Class<?>, List<FieldMouseHandler>>();

		// find all instances of AnnotatedString
		List<FieldMouseHandlerExtension> instances =
			ClassSearcher.getInstances(FieldMouseHandlerExtension.class);
		for (FieldMouseHandlerExtension fieldMouseHandler : instances) {
			addHandler(map, fieldMouseHandler);
		}

		return map;
	}

	private void addHandler(Map<Class<?>, List<FieldMouseHandler>> map,
			FieldMouseHandler fieldMouseHandler) {
		Class<?>[] supportedLocations = fieldMouseHandler.getSupportedProgramLocations();
		for (Class<?> element2 : supportedLocations) {
			List<FieldMouseHandler> list = map.get(element2);
			if (list == null) {
				list = new ArrayList<FieldMouseHandler>();
			}
			list.add(fieldMouseHandler);
			map.put(element2, list);
		}
	}

	private Map<Class<?>, List<FieldMouseHandler>> getFieldMouseHandlers() {
		if (fieldMouseHandlers == null) {
			fieldMouseHandlers = initializeFieldMouseHandlers();
		}

		return fieldMouseHandlers;
	}

	private List<FieldMouseHandler> getFieldMouseHandlersForLocation(Class<?> programLocationClass) {
		return getFieldMouseHandlers().get(programLocationClass);
	}

	@Override
	public void buttonPressed(ProgramLocation location, FieldLocation fieldLocation,
			ListingField field, MouseEvent event) {
		Object clickedFieldElement = field.getClickedObject(fieldLocation);
		fieldElementClicked(clickedFieldElement, location, event);
	}

	@Override
	public void addFieldMouseHandler(FieldMouseHandler handler) {
		addHandler(getFieldMouseHandlers(), handler);

	}
}
