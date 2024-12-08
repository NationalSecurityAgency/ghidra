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

import ghidra.features.bsim.gui.BSimServerManager;
import ghidra.features.bsim.query.BSimJDBCDataSource;
import ghidra.features.bsim.query.BSimServerInfo;

class ConnectionPoolStatus {
	BSimServerInfo serverInfo;

	final boolean isActive;
	final int activeCount;
	final int idleCount;

	ConnectionPoolStatus(BSimServerInfo serverInfo) {
		this.serverInfo = serverInfo;

		BSimJDBCDataSource dataSource = BSimServerManager.getDataSourceIfExists(serverInfo);
		if (dataSource == null) {
			isActive = false;
			activeCount = 0;
			idleCount = 0;
		}
		else {
			isActive = true;
			activeCount = dataSource.getActiveConnections();
			idleCount = dataSource.getIdleConnections();
		}
	}
}
