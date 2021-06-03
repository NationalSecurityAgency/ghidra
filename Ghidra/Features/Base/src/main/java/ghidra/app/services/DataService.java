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
package ghidra.app.services;

import ghidra.app.context.ListingActionContext;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.data.DataType;

/**
 * Service for creating data
 */
@ServiceInfo(description = "Data creation service")
public interface DataService {

	/**
	 * Determine if create data is permitted on the specified location. If the
	 * location is contained within the current program selection, the entire
	 * selection is examined.
	 *
	 * @param context the context containing program, location, and selection information
	 * @return true if create data is allowed, else false.
	 */
	public boolean isCreateDataAllowed(ListingActionContext context);

	/**
	 * Apply the given data type at a location.
	 *
	 * @param dt data type to create at the location
	 * @param context the context containing program, location, and selection information
	 * @param enableConflictHandling if true, the service may prompt the user to resolve data 
	 *        conflicts
	 * @return true if the data could be created at the current location
	 */
	public boolean createData(DataType dt, ListingActionContext context,
			boolean enableConflictHandling);
}
