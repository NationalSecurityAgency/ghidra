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
package ghidra.program.model.lang;

import ghidra.program.model.data.DataTypeComponent;

/**
 * Interface for objects that can provide new instances of dataTypes
 */

public interface DataTypeProviderContext {

	/**
	 * Get a unique name for a data type given a prefix name
	 *
	 * @param baseName prefix for unique name
	 *
	 * @return a unique data type name
	 */
	public String getUniqueName(String baseName);

	/**
	 * Get one data type from buffer at the current position plus offset.
	 *
	 * @param offset the displacement from the current position.
	 *
	 * @return the data type at offset from the current position.
	 *
	 * @throws IndexOutOfBoundsException if offset is negative
	 */
	public DataTypeComponent getDataTypeComponent(int offset);

	/**
	 * Get an array of DataTypeComponents that begin at start or before end.
	 *   DataTypes that begin before start are not returned
	 *   DataTypes that begin before end, but terminate after end ARE returned
	 *
	 * @param start start offset
	 * @param end end offset
	 *
	 * @return array of DataTypes that exist between start and end.
	 */
	public DataTypeComponent[] getDataTypeComponents(int start, int end);

	/**
	 * Get the maximum contiguous offset that can be used to retrieve from the buffer.
	 *      This could be til:
	 *          the end of the block of memory is hit.
	 *          til the end of a structure.
	 */
//	public int getMaxOffset();

	/**
	 * Get the memory buffer at for this context's location.
	 *
	 * @return the memory buffer on this location
	 *         Could be null if there is no memory defined here.
	 */
//	public MemBuffer getMemoryBuffer();
}
