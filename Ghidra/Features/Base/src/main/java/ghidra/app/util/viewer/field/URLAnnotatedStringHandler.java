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
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Program;
import ghidra.util.BrowserLoader;
import ghidra.util.Msg;

import java.awt.Color;
import java.net.MalformedURLException;
import java.net.URL;

import docking.widgets.fieldpanel.field.AttributedString;

/**
 * An annotated string handler that allows handles annotations that begin with 
 * {@link #SUPPORTED_ANNOTATIONS}.  This class expects one or two strings following the annotation.
 * The first string will be treated as a Java {@link URL} and the optional second string will
 * be treated as display text.  If there is not display text, then the URL will be 
 * displayed.
 */
public class URLAnnotatedStringHandler implements AnnotatedStringHandler {
	private static final String INVALID_SYMBOL_TEXT = "@url annotation must have a URL string "
		+ "optionally followed by a display string";
	private static final String[] SUPPORTED_ANNOTATIONS = { "url", "hyperlink", "href", "link" };

	@Override
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) throws AnnotationException {

		// if the text is not of adequate size, then show an error string
		if (text.length <= 1) {
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		URL url = getURLForString(text[1]);

		if (url == null) {
			return new AttributedString("Invalid URL annotations - not a URL: " + text[1],
				Color.RED, prototypeString.getFontMetrics(0), false, Color.RED);
		}

		String displayText = url.toExternalForm();
		if (text.length > 2) { // URL and display text
			StringBuffer buffer = new StringBuffer();
			for (int i = 2; i < text.length; i++) {
				buffer.append(text[i]).append(" ");
			}
			buffer.deleteCharAt(buffer.length() - 1); // remove last space
			displayText = buffer.toString();
		}

		return new AttributedString(displayText, prototypeString.getColor(0),
			prototypeString.getFontMetrics(0), true, prototypeString.getColor(0));
	}

	@Override
	public String[] getSupportedAnnotations() {
		return SUPPORTED_ANNOTATIONS;
	}

	private URL getURLForString(String urlString) {
		URL url = null;
		try {
			url = new URL(urlString);
		}
		catch (MalformedURLException exc) {
			// we return null
		}

		return url;
	}

	public boolean handleMouseClick(String[] annotationParts, Navigatable navigatable,
			ServiceProvider serviceProvider) {
		String urlString = annotationParts[1];
		URL url = getURLForString(urlString);
		if (url != null) {
			if (GhidraURL.PROTOCOL.equals(url.getProtocol())) {
				ProgramManager programManager = serviceProvider.getService(ProgramManager.class);
				return programManager.openProgram(url, ProgramManager.OPEN_CURRENT) != null;
			}
			BrowserLoader.display(url, null, serviceProvider);
			return true;
		}

		Msg.showError(this, null, "Invalid URL", "Unable to create a Java URL " +
			"object from string: " + urlString);

		return false;
	}

	@Override
	public String getDisplayString() {
		return "URL";
	}

	@Override
	public String getPrototypeString() {
		return "{@url http://www.example.com}";
	}

}
