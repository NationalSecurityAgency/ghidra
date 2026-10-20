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
package ghidra.framework.client;

import java.io.IOException;
import java.net.URL;

import docking.widgets.OptionDialog;
import ghidra.util.SystemUtilities;

/**
 * {@link DefaultGhidraUrlAllowListProvider} is an allow list provider for cases where 
 * the user should be prompted when access has not yet been decided.
 * <p>
 * Prompting uses {@code stdin/stdout} when {@link SystemUtilities#isInHeadlessMode()} returns true,
 * otherwise Swing GUI is used via {@link OptionDialog} popup.
 */
public class DefaultGhidraUrlAllowListProvider extends AbstractUrlAllowListProvider {

	@Override
	public boolean isAllowed(URL url) {

		Boolean allowed = accessAllowed(url);
		if (allowed != null) {
			return allowed;
		}

		if (SystemUtilities.isInHeadlessMode()) {
			String prompt = "Allow server access to " + getBaseURL(url) + " (y|n): ";
			allowed = getConsoleYesNoUserResponse(prompt);
		}
		else {
			int resp = OptionDialog.showOptionDialog(null, "Verify Server Access",
				"Allow server access to " + getBaseURL(url) +
					"?\nThis decision will be retained for subsequent access decisions.",
				"&Yes", "&No", OptionDialog.QUESTION_MESSAGE);
			if (resp == OptionDialog.CANCEL_OPTION) {
				return false; // disallow connection without updating allow list
			}
			allowed = (resp == OptionDialog.OPTION_ONE);
		}

		UrlAllowListManager.updateAccess(url, allowed);
		return allowed;
	}

	private boolean getConsoleYesNoUserResponse(String prompt) {

		try {
			boolean closed = false;
			while (!closed) {

				// Flush any stale stdin data before prompting for response
				while (System.in.available() > 0) {
					System.in.read();
				}

				// Prompt user on stdout
				System.out.print(prompt);

				// Read response line from stdin
				StringBuilder buf = new StringBuilder();
				while (true) {
					int c = System.in.read();
					if (c <= 0) {
						closed = true;
						break;
					}
					if (c == '\r' || c == '\n') {
						break;
					}
					buf.append((char) c);
				}

				// Check for yes/no response
				String resp = buf.toString();
				if ("y".equalsIgnoreCase(resp) || "yes".equalsIgnoreCase(resp)) {
					return true;
				}
				if ("n".equalsIgnoreCase(resp) || "no".equalsIgnoreCase(resp)) {
					return false;
				}
				System.out.println("Invalid response");
			}
		}
		catch (IOException e) {
			// ignore
		}
		return false;
	}
}
