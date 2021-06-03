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
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.awt.Color;

import docking.widgets.fieldpanel.field.AttributedString;

/**
 * An annotated string handler that allows handles annotations that begin with
 * {@link #SUPPORTED_ANNOTATIONS}.  This class expects one string following the annotation
 * text that is an address string and will display that string as its display text.
 */
public class AddressAnnotatedStringHandler implements AnnotatedStringHandler {
	private static final String INVALID_SYMBOL_TEXT = "@address annotation must have an address"
		+ "string";
	private static final String[] SUPPORTED_ANNOTATIONS = { "address", "addr" };

	@Override
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) throws AnnotationException {
		// if the text is not of adequate size, then show an error string
		if (text.length <= 1) {
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		if (program == null) { // this can happen during merge operations
			return createUndecoratedString(prototypeString, text);
		}

		Address address = program.getAddressFactory().getAddress(text[1]);

		if (address == null) {
			return new AttributedString("No address: " + text[1], Color.RED,
				prototypeString.getFontMetrics(0), false, null);
		}

		String addressText = address.toString();
		if (text.length > 2) { // address and display text
			StringBuffer buffer = new StringBuffer();
			for (int i = 2; i < text.length; i++) {
				buffer.append(text[i]).append(" ");
			}
			buffer.deleteCharAt(buffer.length() - 1);  // remove last space
			addressText = buffer.toString();
		}

		return new AttributedString(addressText, prototypeString.getColor(0),
			prototypeString.getFontMetrics(0), true, prototypeString.getColor(0));
	}

	private AttributedString createUndecoratedString(AttributedString prototypeString, String[] text) {
		StringBuilder buffer = new StringBuilder();
		for (String string : text) {
			buffer.append(string).append(" ");
		}

		return new AttributedString(buffer.toString(), Color.LIGHT_GRAY,
			prototypeString.getFontMetrics(0));
	}
	@Override
	public String[] getSupportedAnnotations() {
		return SUPPORTED_ANNOTATIONS;
	}

	@Override
	public boolean handleMouseClick(String[] annotationParts, Navigatable sourceNavigatable,
			ServiceProvider serviceProvider) {
		GoToService goToService = serviceProvider.getService(GoToService.class);

		Program program = sourceNavigatable.getProgram();
		String addressText = annotationParts[1];
		Address address = program.getAddressFactory().getAddress(addressText);
		if (address != null) {
			return goToService.goTo(sourceNavigatable, address);
		}

		Msg.showInfo(getClass(), null,
			"No address: " + addressText, "Unable to locate address \"" + addressText + "\"");
		return false;
	}

	@Override
	public String getDisplayString() {
		return "Address";
	}

	@Override
	public String getPrototypeString() {
		return "{@address 0x00}";
	}

}
