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
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.util.ProgramLocation;
import ghidra.util.bean.field.AnnotatedTextFieldElement;

/**
 * A handler to process {@link ghidra.util.bean.field.AnnotatedTextFieldElement} clicks.
 */
public class AnnotatedStringFieldMouseHandler implements FieldMouseHandlerExtension {
	private static final Class<?>[] SUPPORTED_CLASSES =
		new Class[] { AnnotatedTextFieldElement.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {
		if (mouseEvent.getClickCount() != 2 || mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}
		return ((AnnotatedTextFieldElement) clickedObject).handleMouseClicked(sourceNavigatable,
			serviceProvider);
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}
}
