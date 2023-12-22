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
package ghidra.features.bsim.query.facade;

import ghidra.features.bsim.query.description.DatabaseInformation;

public class DatabaseInfo {

	private final String serverURL;
	private final DatabaseInformation databaseInformation;

	public DatabaseInfo(String serverURL, DatabaseInformation databaseInformation) {
		this.serverURL = serverURL;
		this.databaseInformation = databaseInformation;
	}

	public String getServerURL() {
		return serverURL;
	}

	public String getName() {
		return databaseInformation.databasename;
	}

	public String getOwner() {
		return databaseInformation.owner;
	}

	public String getDescription() {
		return databaseInformation.description;
	}

	public String getVersion() {
		return Short.toString(databaseInformation.major) + "." +
			Short.toString(databaseInformation.minor);
	}

	public boolean isReadOnly() {
		return databaseInformation.readonly;
	}

	@Override
	public String toString() {
		// @formatter:off
		return "Database: " + serverURL + 
					"\ntName: " + getName() + 
					"\n\tOwner: " + getOwner() + 
					"\n\tVersion: " + getVersion() + 
					"\n\tDescription: " + getDescription();
		// @formatter:on
	}
}
