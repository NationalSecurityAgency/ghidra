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

import java.net.URL;

/**
 * {@link UrlAllowListProvider} provides the URL allow list provider interface which facilitates
 * obtaining an access decision for a specified server URL.
 */
public interface UrlAllowListProvider {

	/**
	 * Check if a server connection is permitted.  If permitted, the server will be added
	 * to the cached allow list.  This method will return true for opaque or non-server URLs.
	 * 
	 * @param url server URL
	 * @return true if connection is allowed and may proceed, else false if denied
	 */
	public abstract boolean isAllowed(URL url);
}
