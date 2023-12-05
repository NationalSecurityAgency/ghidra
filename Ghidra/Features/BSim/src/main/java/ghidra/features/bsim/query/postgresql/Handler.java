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
package ghidra.features.bsim.query.postgresql;

import java.io.IOException;
import java.net.*;

/**
 * Dummy stream handler, so we can create URL objects with protocol "postgresql"
 */
public class Handler extends URLStreamHandler {

	private static String MY_PARENT_PACKAGE = "ghidra.features.bsim.query";
	private static String PROTOCOL_HANDLER_PKGS_PROPERTY = "java.protocol.handler.pkgs";

	@Override
	protected URLConnection openConnection(URL u) throws IOException {
		throw new IOException("Trying to open connection with dummy handler");
	}

	public static void registerHandler() {
		String pkgs = System.getProperty(PROTOCOL_HANDLER_PKGS_PROPERTY);
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
}
