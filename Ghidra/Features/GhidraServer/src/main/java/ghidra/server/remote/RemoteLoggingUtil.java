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
package ghidra.server.remote;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.server.RepositoryManager;

public class RemoteLoggingUtil {

	private static Logger log = LogManager.getLogger(GhidraServer.class);

	/**
	 * Generate log message that contains inforamtion message.
	 * 
	 * General format where client host may be omitted if unable to determine:
	 * <pre>
	 *   msg (host)
	 * </pre>
	 * @param msg log message (required)
	 * @param user user name or null
	 */
	public static void log(String msg) {
		log(null, null, msg, null, false);
	}

	/**
	 * Generate log message that contains information message and user details.
	 * 
	 * General format where some portions may be omitted if null:
	 * <pre>
	 *   msg (user@host)
	 * </pre>
	 * @param msg log message (required)
	 * @param user user name or null
	 */
	public static void log(String msg, String user) {
		log(null, null, msg, user, false);
	}

	/**
	 * Generate information or error log message that contains repository, path, message 
	 * and user details.
	 * 
	 * General format where some portions may be omitted if null:
	 * <pre>
	 *   [repositoryName]path: msg (user@host)
	 * </pre>
	 * @param repositoryName repository name or null
	 * @param path repository file path or null
	 * @param msg log message (required)
	 * @param user user name or null
	 * @param error true if error log else info
	 */
	public static void log(String repositoryName, String path, String msg, String user,
			boolean error) {
		StringBuilder buf = new StringBuilder();
		if (repositoryName != null) {
			buf.append("[");
			buf.append(repositoryName);
			buf.append("]");
		}
		String host = RepositoryManager.getRMIClient();
		String userStr = user;
		if (userStr != null) {
			if (host != null) {
				userStr += "@" + host;
			}
		}
		else {
			userStr = host;
		}
		if (path != null) {
			buf.append(path);
		}
		if (repositoryName != null || path != null) {
			buf.append(": ");
		}
		buf.append(msg);
		if (userStr != null) {
			buf.append(" (");
			buf.append(userStr);
			buf.append(")");
		}
		if (error) {
			log.error(buf.toString());
		}
		else {
			log.info(buf.toString());
		}
	}

	private RemoteLoggingUtil() {
		// no instantiation
	}

}
