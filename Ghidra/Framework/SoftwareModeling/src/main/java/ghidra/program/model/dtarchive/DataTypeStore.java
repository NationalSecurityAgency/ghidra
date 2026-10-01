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

import ghidra.framework.model.DomainObject;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.ProgramArchitecture;

/**
 * A DatatypeStore provides a collection of {@link DataType}s and related
 * resources.  The associated {@link DataTypeManager} instance is provided to facilitate
 * queries and management of the {@link DataType}s. 
 */
public interface DataTypeStore extends DomainObject {

	/**
	 * {@return the data type manager for this archive}
	 */
	public DataTypeManager getDataTypeManager();

	/**
	 * {@return the type of the archive (or if it is a program)}
	 */
	public ArchiveType getArchiveType();

	/**
	 * Get the optional program architecture details associated with this archive
	 * @return program architecture details or null if none
	 */
	public ProgramArchitecture getProgramArchitecture();

	/**
	 * Get the program architecture information which has been associated with this 
	 * datatype manager.  If {@link #getProgramArchitecture()} returns null this method
	 * may still return information if the program architecture was set on an archive 
	 * and conditions exist which prevent architecture from taking affect.
	 * @return program architecture summary if it has been set, else null
	 */
	public String getProgramArchitectureSummary();

}
