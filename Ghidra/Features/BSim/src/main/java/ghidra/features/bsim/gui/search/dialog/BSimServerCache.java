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
package ghidra.features.bsim.gui.search.dialog;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.facade.QueryDatabaseException;

/**
 * Caches BSim database info for a Bsim database connection
 */
public class BSimServerCache {
	private BSimServerInfo serverInfo;
	private DatabaseInformation databaseInfo;
	private LSHVectorFactory lshVectorFactory;

	public BSimServerCache(BSimServerInfo severInfo) throws QueryDatabaseException {
		this.serverInfo = severInfo;
		initialize();
	}

	public BSimServerInfo getServerInfo() {
		return serverInfo;
	}

	public DatabaseInformation getDatabaseInformation() {
		return databaseInfo;
	}

	/**
	 * Get cached {@link LSHVectorFactory} for the active BSim Function Database 
	 * @return vector factory or null if DB server not set or never connected
	 */
	public LSHVectorFactory getLSHVectorFactory() {
		return lshVectorFactory;
	}

	private void initialize() throws QueryDatabaseException {
		try (FunctionDatabase database = serverInfo.getFunctionDatabase(false)) {
			if (!database.initialize()) { // error message will be set on failure
				String errorMessage = database.getLastError().message;
				if (database.getLastError().category == ErrorCategory.Nodatabase) {
					errorMessage = "Database does not exist";
				}
				throw new QueryDatabaseException(errorMessage);
			}
			databaseInfo = database.getInfo();
			lshVectorFactory = database.getLSHVectorFactory();
		}
	}

}
