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
package ghidra.net;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

public class UriUtil {

	/**
	 * Appends elements to the path part of a URI, preserving the other parts of the URI.
	 * <p>
	 * Note: %2F (eg. '/') encoded characters are normalized to plain '/' when the URI is
	 * reconstructed after appending the new path elements.
	 * 
	 * @param uri base URI to append to
	 * @param pathSegments list of strings that will be appended to the path, where each element
	 *   will be separated by slash "/" delimiters from the previous elements.  Elements can
	 *   have a leading slash "/" already or one will be provided.  Empty or null elements
	 *   are skipped.
	 * @return new URI with a path element that has been modified
	 * @throws URISyntaxException if error
	 */
	public static URI appendPath(URI uri, String... pathSegments) throws URISyntaxException {

		StringBuilder sb = new StringBuilder();
		sb.append(Objects.requireNonNullElse(uri.getPath(), ""));

		for (String s : pathSegments) {
			if (s == null || s.isEmpty()) {
				continue;
			}
			if ((sb.isEmpty() || sb.charAt(sb.length() - 1) != '/') && !s.startsWith("/")) {
				sb.append("/");
			}
			sb.append(s);
		}

		return new URI(uri.getScheme(), uri.getRawAuthority(), sb.toString(),
			uri.getRawQuery(), uri.getRawFragment());
	}

}
