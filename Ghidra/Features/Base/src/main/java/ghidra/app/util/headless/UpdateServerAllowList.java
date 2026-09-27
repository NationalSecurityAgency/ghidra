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
package ghidra.app.util.headless;

import java.io.IOException;
import java.net.*;
import java.util.*;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.client.*;
import ghidra.framework.protocol.ghidra.Handler;
import ghidra.util.Msg;

/**
 * {@link UpdateServerAllowList} utility for managing the Server Allow List.
 * See {@link UrlAllowListManager}.
 */
public class UpdateServerAllowList implements GhidraLaunchable {

	private static final String INVOCATION_NAME_PROPERTY = "UpdateServerAllowList.Name";

	public UpdateServerAllowList() {
		// Required for GhidraLaunchable
	}

	private URL parseURL(String urlString) throws MalformedURLException {
		URI uri = URI.create(urlString);
		return uri.toURL();
	}

	private void checkMoreArgs(int currentArgIndex, String[] args) {
		if (currentArgIndex == args.length - 1) {
			usage(args);
		}
	}

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws IOException {
		Application.initializeApplication(layout, new ApplicationConfiguration());
		if (args.length == 0) {
			usage(args);
		}

		// NOTE: May need other protocol handlers to be registered to avoid URL exceptions
		Handler.registerHandler();

		try {
			boolean printList = false;
			for (int i = 0; i < args.length; i++) {
				String arg = args[i];
				switch (arg) {

					case "-allow":
						checkMoreArgs(i, args);
						URL url = parseURL(args[++i]);
						UrlAllowListManager.updateAccess(url, true);
						break;

					case "-disallow":
						checkMoreArgs(i, args);
						url = parseURL(args[++i]);
						UrlAllowListManager.updateAccess(url, false);
						break;

					case "-clear":
						checkMoreArgs(i, args);
						url = parseURL(args[++i]);
						UrlAllowListManager.clearAccessEntry(url);
						break;

					case "-clearAll":
						UrlAllowListManager.clearAll();
						break;

					case "-list":
						printList = true;
						break;

					default:
						usage(args);
				}
			}

			if (printList) {
				Map<ServerSpecification, AccessRecord> accessMap =
					UrlAllowListManager.getAccessMap();
				List<ServerSpecification> servers = new ArrayList<>(accessMap.keySet());
				if (servers.isEmpty()) {
					System.out.println("Server Allow List is empty.");
				}
				else {
					Collections.sort(servers);
					System.out.println("Server Allow List:");
					for (ServerSpecification svr : servers) {

						AccessRecord accessRecord = accessMap.get(svr);
						String access = accessRecord.accessAllowed() ? "ALLOW   " : "DISALLOW";
						Date date = new Date(accessRecord.time());

						System.out.println(
							"   " + access + " " + svr.toUrlString() + " (" + date + ")");
					}
				}
			}
		}
		catch (Exception e) {
			Msg.error("Exception processing Allow List updates", e);
		}
	}

	private static void usage(String[] args) {
		for (int i = 0; i < args.length; i++) {
			System.err.println("arg " + i + ": " + args[i]);
		}
		String invocationName = System.getProperty(INVOCATION_NAME_PROPERTY);

		StringBuffer buf = new StringBuffer();
		buf.append("\nUsage: ");
		buf.append(
			invocationName != null ? invocationName : UpdateServerAllowList.class.getSimpleName());
		buf.append(
			" [-allow <protocol>://<hostname>:<port>] [-disallow <protocol>://<hostname>:<port>] [-clear <protocol>://<hostname>:<port>] [-clearAll] [-list]\n");
		System.err.println(buf.toString());
		System.exit(0);
	}
}
