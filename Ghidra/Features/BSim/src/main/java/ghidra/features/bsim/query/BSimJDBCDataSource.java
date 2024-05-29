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

import java.sql.Connection;
import java.sql.SQLException;

import ghidra.features.bsim.query.FunctionDatabase.ConnectionType;
import ghidra.features.bsim.query.FunctionDatabase.Status;

public interface BSimJDBCDataSource {

	Status getStatus();

	/**
	 * Get DB {@link Connection} object performing any required authentication.  
	 * @return {@link Connection} object
	 * @throws SQLException if connection fails
	 */
	Connection getConnection() throws SQLException;

	ConnectionType getConnectionType();

	/**
	 * Get the server info that corresponds to this data source.  It is important to note
	 * that the returned instance is normalized for the purpose of caching and may not
	 * match the original server info object used to obtain this data source instance.
	 * @return server info
	 */
	BSimServerInfo getServerInfo();

	/**
	 * Get the number of active connections in the associated connection pool
	 * @return number of active connections
	 */
	int getActiveConnections();

}
