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
package ghidra.program.model.data;

import ghidra.framework.model.RuntimeIOException;
import ghidra.program.database.data.TransientDataTypeManager;

/**
 * Basic implementation of the DataTypeManger interface for those data type managers that
 * originate in an archive and not a program.
 *
 * @deprecated use {@link TransientDataTypeManager}
 */
@Deprecated(forRemoval = true, since = "12.2")
public class StandAloneDataTypeManager extends TransientDataTypeManager {

	/**
	 * Constructor for new temporary data-type manager using the default DataOrganization.
	 * Note that this manager does not support the save or saveAs operation.
	 * @param name temporary archive and datatype manager name
	 * @throws RuntimeIOException if database error occurs during creation
	 * @deprecated use {@link TransientDataTypeManager}
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public StandAloneDataTypeManager(String name) throws RuntimeIOException {
		super(name);
	}

	/**
	 * Constructor for new temporary data-type manager using a specified DataOrganization.
	 * Note that this manager does not support the save or saveAs operation.
	 * @param name temporary archive and datatype manager name
	 * @param dataOrganzation applicable data organization
	 * @throws RuntimeIOException if database error occurs during creation
	 * @deprecated use {@link TransientDataTypeManager}
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public StandAloneDataTypeManager(String name, DataOrganization dataOrganzation)
			throws RuntimeIOException {
		super(name, dataOrganzation);
	}
}
