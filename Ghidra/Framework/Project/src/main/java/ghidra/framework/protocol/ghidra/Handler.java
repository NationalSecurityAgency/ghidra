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
package ghidra.framework.protocol.ghidra;

import java.io.IOException;
import java.net.*;
import java.util.*;

import ghidra.framework.client.ClientUtil;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.NotFoundException;

/**
 * <code>Handler</code> provides a "ghidra" URL protocol handler which
 * corresponds to the <code>GhidraURLConnection</code> implementation.
 */
public class Handler extends URLStreamHandler {

	private static final String MY_PARENT_PACKAGE = "ghidra.framework.protocol";

	private static final String PROTOCOL_HANDLER_PKGS_PROPERTY = "java.protocol.handler.pkgs";

	/**
	 * Register the "ghidra" URL protocol Handler.
	 * Alternatively, the protocol handler can be explicitly used when instantiating 
	 * a ghidra URL:
	 * <pre>
	 *   URL url = new URL(null, "ghidra://myGhidraServer/Test", new ghidra.framework.protocol.ghidra.Handler());
	 * </pre>
	 * It is also important that a <code>ClientAuthenticator</code> also be registered.
	 * @see ClientUtil#setClientAuthenticator(ghidra.framework.client.ClientAuthenticator)
	 */
	public static void registerHandler() {

		String pkgs = System.getProperty("java.protocol.handler.pkgs");
		if (pkgs != null) {
			if (pkgs.indexOf(MY_PARENT_PACKAGE) >= 0) {
				return; // avoid multiple registrations
			}
			pkgs = pkgs + "|" + MY_PARENT_PACKAGE;
		}
		else {
			pkgs = MY_PARENT_PACKAGE;
		}

		System.setProperty(PROTOCOL_HANDLER_PKGS_PROPERTY, pkgs);
	}
	
	/**
	 * Determine if the specified url is supported and that any required 
	 * protocol extensions are recognized.
	 * @param url
	 * @return true if support ghidra URL
	 */
	public static boolean isSupportedURL(URL url) {
		if (!GhidraURL.PROTOCOL.equals(url.getProtocol())) {
			return false;
		}
		if (url.getAuthority() != null) {
			// assume standard ghidra URL (ghidra://...)
			return true;
		}
		try {
			return getProtocolExtensionHandler(url) != null;
		}
		catch (MalformedURLException | NotFoundException e) {
			return false;
		}
	}
	
	private static GhidraProtocolHandler getProtocolExtensionHandler(URL url) throws MalformedURLException, NotFoundException {
		String path = url.getPath();
		int index = path.indexOf("://");
		if (index <= 0) {
			throw new MalformedURLException("invalid ghidra URL: " + url);
		}
		String extensionName = path.substring(0, index);
		GhidraProtocolHandler protocolHandler = findGhidraProtocolHandler(extensionName);
		if (protocolHandler == null) {
			throw new NotFoundException("ghidra protocol extension handler (" + extensionName +
				") not found");
		}
		return protocolHandler;
	}

	@Override
	protected URLConnection openConnection(URL url) throws IOException {

		if (!GhidraURL.PROTOCOL.equals(url.getProtocol())) {
			throw new IllegalArgumentException("unsupported URL protocol: " + url.getProtocol());
		}

		// Need to check for protocol extension if URL is of form ghidra:<extension-url>
		// Example:  ghidra:http://host/repo/folder/filename
		if (url.getAuthority() == null && !url.getPath().startsWith("/")) {
			// check for protocol handler which provides access to a full repository
			// while specifying a specific folder/file within the repository.  
			// The repository root is inferred from the URL path.
			try {
				GhidraProtocolHandler protocolHandler = getProtocolExtensionHandler(url);
				// strip ghidra protocol specifier from URL
				url = new URL(url.toExternalForm().substring(GhidraURL.PROTOCOL.length() + 1));
				return new GhidraURLConnection(url, protocolHandler);
			}
			catch (NotFoundException e) {
				throw new IOException("unsupported ghidra URL", e);
			}
		}

		return new GhidraURLConnection(url);
	}

	private static Collection<GhidraProtocolHandler> protocolHandlers;

	private static void loadGhidraProtocolHandlers() {
		protocolHandlers = new ArrayList<>();
		List<Class<? extends GhidraProtocolHandler>> classes =
			ClassSearcher.getClasses(GhidraProtocolHandler.class);
		for (Class<?> c : classes) {
			try {
				protocolHandlers.add((GhidraProtocolHandler) c.newInstance());
			}
			catch (InstantiationException | IllegalAccessException e) {
				Msg.error(Handler.class,
					"Failed to instantiate ghidra protocol extension handler: " + c.getName());
			}
		}
	}

	private static GhidraProtocolHandler findGhidraProtocolHandler(String extensionName) {
		synchronized (Handler.class) {
			if (protocolHandlers == null) {
				loadGhidraProtocolHandlers();
			}
		}
		for (GhidraProtocolHandler handler : protocolHandlers) {
			if (handler.isExtensionSupported(extensionName)) {
				return handler;
			}
		}
		return null;
	}

}
