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
package ghidra.features.bsim.query;

import java.net.MalformedURLException;
import java.net.URL;

import ghidra.features.bsim.query.client.PostgresFunctionDatabase;
import ghidra.features.bsim.query.elastic.ElasticDatabase;
import ghidra.features.bsim.query.file.H2FileFunctionDatabase;
import ghidra.framework.protocol.ghidra.GhidraURL;

public class BSimClientFactory {

	/**
	 * Build a root URL for connecting to a BSim database.
	 *   1) A valid protocol must be provided.
	 *   2) There must be a path of exactly 1 element, which names the specific repository
	 * Acceptable protocols are  postgresql://  https://,  (or possibly http://) file:/
	 *  
	 * @param urlString the URL to build
	 * @return the parsed URL object
	 * @throws MalformedURLException if the URL string cannot be parsed
	 */
	public static URL buildURL(String urlString) throws MalformedURLException {
		URL url = new URL(urlString);
		checkBSimServerURL(url);
		return url;
	}

	/**
	 * Validate BSim DB URL.
	 * Acceptable protocols are  postgresql://  https://,  (or possibly http://) file:/
	 * @param url BSim DB URL
	 * @throws MalformedURLException if the URL string is not a support BSim DB URL
	 */
	public static void checkBSimServerURL(URL url) throws MalformedURLException {
		String protocol = url.getProtocol();
		if (!protocol.equals("postgresql") && !protocol.equals("https") &&
			!protocol.equals("elastic") && !protocol.equals("file")) {
			throw new MalformedURLException("Protocol not permissable for BSim URL");
		}
		String path = url.getPath();
		if (path == null || path.length() == 0 || path.equals("/")) {
			throw new MalformedURLException("BSim URL missing DB name/path");
		}
		if (!"file".equals(protocol) && path.indexOf('/', 1) >= 0) {
			throw new MalformedURLException("BSim URL must specify exactly 1 path element");
		}
	}

	/**
	 * Construct the root URL to a specific BSim repository given a "related" URL.
	 * The root URL will have an explicit protocol, a hostname + other mods (the authority), and 1 level of path
	 *    this first level path indicates the particular repository being referenced on the host.
	 * The "related" URL -url- can be an explicitly provided URL pointing to the BSim repository,
	 *    possibly with additional path levels, which are simply stripped from the final root URL.
	 * Alternately -url- can reference a ghidra server, as indicated by the "ghidra" protocol.
	 *    In this case the true BSim URL is derived from ghidra URL in some way
	 * @param urlString is the "related" URL
	 * @return the root BSim URL
	 * @throws MalformedURLException if the given URL string cannot be parsed
	 * @throws IllegalArgumentException if local ghidra URL is specified
	 */
	public static URL deriveBSimURL(String urlString)
			throws IllegalArgumentException, MalformedURLException {
		URL url = new URL(urlString);	// URL used only for parsing purposes
		String protocol = url.getProtocol();
		if ("postgresql".equals(protocol) || "https".equals(protocol) ||
			"elastic".equals(protocol) || "file".equals(protocol)) {
			checkBSimServerURL(url);
			return url; // URL already corresponds to BSim server protocol
		}
		if (!GhidraURL.isServerRepositoryURL(url)) {
			throw new IllegalArgumentException("Unable to infer BSim URL from: " + url);
		}
		String path = url.getPath();							// Get the full path of the URL
		if (path == null || path.length() == 0 || path.equals("/")) {		// There must always be some kind of path, so we can derive the repository
			throw new MalformedURLException("URL is missing a repository path");
		}
		int endrepos = path.indexOf('/', 1);	// Find the end of the first level of the path
		String repositoryURL;
		if (url.getProtocol().equals(GhidraURL.PROTOCOL)) {	// Is this a ghidra URL
			// TODO: we could set things up so that a ghidra server could be queried for its associated BSim server
			// "ghidra://host/repo?service=bsim"
			// String repositoryURL = "ghidra://" + ghidraURL.getAuthority() + "?service=bsim";

			// Currenly all we do is assume that the BSim server is a PostgreSQL server
			// on the same host and with the same repo name as the ghidra server
			repositoryURL = "postgresql://" + url.getHost();		// Just use the hostname
		}
		else {
			// For all other URL forms, we assume we are being handed the protocol and hostname (authority)
			// explicitly. We keep them for the final BSim URL
			repositoryURL = url.getProtocol() + "://" + url.getAuthority();
		}
		// Attach the first level of the path, which indicates the repository
		if (endrepos < 0) {
			repositoryURL = repositoryURL + path;
		}
		else {
			repositoryURL = repositoryURL + path.substring(0, endrepos);
		}
		return buildURL(repositoryURL);
	}

	/**
	 * Given the URL for a BSim server construct the appropriate BSim client object (implementing FunctionDatabase)
	 * @param bsimServerInfo  BSim server details
	 * @param async true if database commits should be asynchronous
	 * @return the database client
	 */
	public static FunctionDatabase buildClient(BSimServerInfo bsimServerInfo, boolean async) {
		try {
			return buildClient(bsimServerInfo.toURL(), async);
		}
		catch (MalformedURLException e) {
			throw new RuntimeException(e);  // unexpected
		}
	}

	/**
	 * Given the URL for a BSim server construct the appropriate BSim client object 
	 * (implementing FunctionDatabase).  Returned instance must be 
	 * {@link FunctionDatabase#close() closed} when done using it to prevent depletion
	 * of database connections.
	 * @param bsimURL  URL supplied by the user
	 * @param async true if database commits should be synchronous
	 * @return the database client
	 * @throws MalformedURLException if there's a problem creating the elastic database
	 */
	public static FunctionDatabase buildClient(URL bsimURL, boolean async)
			throws MalformedURLException {

		String protocol = bsimURL.getProtocol();
		if (protocol.equals("postgresql")) {
			return new PostgresFunctionDatabase(bsimURL, async);
		}
		if (protocol.equals("https") || protocol.equals("elastic")) {
			return new ElasticDatabase(bsimURL);
		}
		if ("file".equals(protocol)) {
			return new H2FileFunctionDatabase(bsimURL);
		}
		throw new MalformedURLException("Unsupported protocol: " + protocol);
	}
}
