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
package ghidra.app.util.bin.format.golang.structmapping;

import java.io.IOException;

/**
 * Interface used by structure mapped classes that need to manually deserialize themselves from
 * the raw data, required when the structure contains variable length fields. 
 * 
 * @param <T> structure mapped type
 */
public interface StructureReader<T> {
	/**
	 * Called after an instance has been created and its context has been initialized, to give
	 * the struct a chance to deserialize itself using the BinaryReaders and such found in the
	 * context information.
	 * 
	 * @throws IOException if error deserializing data for this struct
	 */
	void readStructure() throws IOException;
}
