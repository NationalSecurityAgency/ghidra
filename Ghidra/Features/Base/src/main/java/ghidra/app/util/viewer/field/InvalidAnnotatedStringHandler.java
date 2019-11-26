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
import ghidra.program.model.listing.Program;

import java.awt.Color;

import docking.widgets.fieldpanel.field.AttributedString;

/**
 * An annotated string handler that is used to display an error message string when there is a
 * problem creating an annotated string.
 */
public class InvalidAnnotatedStringHandler implements AnnotatedStringHandler {

	private final String errorText;

	public InvalidAnnotatedStringHandler() {
		errorText = "Invalid Annotation";
	}

	public InvalidAnnotatedStringHandler(String errorText) {
		this.errorText = errorText;
	}

	@Override
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) throws AnnotationException {
		return new AttributedString(errorText, Color.RED, prototypeString.getFontMetrics(0));
	}

	@Override
	public String[] getSupportedAnnotations() {
		return new String[0];
	}

	@Override
	public boolean handleMouseClick(String[] annotationParts, Navigatable navigatable,
			ServiceProvider serviceProvider) {
		return false; // we don't handle clicks!!!
	}

	@Override
	public String getDisplayString() {
		return "Invalid";
	}

	@Override
	public String getPrototypeString() {
		return "";
	}
}
