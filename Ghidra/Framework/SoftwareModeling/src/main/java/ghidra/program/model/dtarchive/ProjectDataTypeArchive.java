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
package ghidra.program.model.dtarchive;

import ghidra.program.model.listing.DataTypeArchiveChangeSet;

/**
 * A {@link ProjectDataTypeArchive} is a DataTypeArchive that is stored within a 
 * Ghidra project.
 */
public interface ProjectDataTypeArchive extends PersistentDataTypeArchive {

	/**
	 * Get the project datatype archive changes since the last save as a set of addresses.
	 * @return set of changed addresses within program.
	 */
	public DataTypeArchiveChangeSet getChanges();

}
