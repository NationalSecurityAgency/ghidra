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

import java.net.*;
import java.util.Set;
import java.util.TreeSet;

import docking.widgets.fieldpanel.field.AttributedString;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.ProgramManager;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Program;
import ghidra.util.BrowserLoader;
import ghidra.util.Msg;

/**
 * An annotated string handler that allows handles annotations that begin with
 * {@link #SUPPORTED_ANNOTATIONS}.  This class expects one or two strings following the annotation.
 * The first string will be treated as a Java {@link URL} and the optional second string will
 * be treated as display text.  If there is not display text, then the URL will be
 * displayed.
 * <p>
 * See {@link GhidraServerURLAnnotatedStringHandler} and {@link GhidraLocalURLAnnotatedStringHandler}
 * for GHIDRA URL dummy handlers that are used to facilitate supported Comment Editor annotation types.
 */
public class URLAnnotatedStringHandler implements AnnotatedStringHandler {

	private static final Set<String> allowedProtocols = new TreeSet<>();
	static {
		// Set maintains alphabetical order or protocols
		// The 'ghidra' protocol must be included here since only one shared 
		// annotation handler is used to process all supported URL protocols.
		allowedProtocols.add("ghidra");
		allowedProtocols.add("http");
		allowedProtocols.add("https");
	}

	private static String allowedProtocolsStr = "ghidra, https or http";

	private static final String INVALID_SYMBOL_TEXT =
		"@url annotation must have a URL string optionally followed by a display string";

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
			return new AttributedString("Invalid URL annotation - not a valid URL: " + text[1],
				Messages.ERROR, prototypeString.getFontMetrics(0), false, Messages.ERROR);
		}

		String protocol = url.getProtocol();
		if (!allowedProtocols.contains(protocol)) {
			return new AttributedString(
				"Unsupported URL annotation protocol - " + allowedProtocolsStr + " required:\n" +
					text[1],
				Messages.ERROR, prototypeString.getFontMetrics(0), false, Messages.ERROR);
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
		try {
			return new URI(urlString).toURL();
		}
		catch (MalformedURLException | URISyntaxException e) {
			return null;
		}
	}

	@Override
	public boolean handleMouseClick(String[] annotationParts, Navigatable navigatable,
			ServiceProvider serviceProvider) {
		String urlString = annotationParts[1];
		URL url = getURLForString(urlString);
		if (url != null) {

			String protocol = url.getProtocol();
			if (!allowedProtocols.contains(protocol)) {
				Msg.showError(this, null, "URL Access Not Allowed",
					"Unsupported URL annotation protocol - " + allowedProtocolsStr +
						" required:\n\n" +
						urlString);
				return false;
			}

			if (!ClientUtil.getAllowListProvider().isAllowed(url)) {
				Msg.showError(this, null, "URL Access Not Allowed",
					"Access denied by Server Allow List");
				return false;
			}

			if (GhidraURL.PROTOCOL.equals(url.getProtocol())) {
				ProgramManager programManager = serviceProvider.getService(ProgramManager.class);
				return programManager.openProgram(url, ProgramManager.OPEN_CURRENT) != null;
			}

			BrowserLoader.display(url, null, serviceProvider);
			return true;
		}

		Msg.showError(this, null, "Invalid URL",
			"Invalid URL annotation - not a valid URL: " + urlString);

		return false;
	}

	@Override
	public String getDisplayString() {
		return "HTTP-URL";
	}

	@Override
	public String getPrototypeString() {
		return "{@url https://www.example.com}";
	}

	@Override
	public String getPrototypeString(String dislplayText) {
		return "{@url " + dislplayText.trim() + "}";
	}

}
