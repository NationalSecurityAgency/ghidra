/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.importer;

import ghidra.program.model.address.Address;

/**
 * An interface for handling memory block conflicts 
 * that are encountered during an import.
 * 
 */
public interface MemoryConflictHandler {
    /**
     * An implementation that always overwrites conflicts.
     */
	public final static MemoryConflictHandler ALWAYS_OVERWRITE = new MemoryConflictHandler() {
		public boolean allowOverwrite(Address start, Address end) {
			return true;
		}
	};
    /**
     * An implementation that never overwrites conflicts.
     */
	public final static MemoryConflictHandler NEVER_OVERWRITE = new MemoryConflictHandler() {
		public boolean allowOverwrite(Address start, Address end) {
			return false;
		}
	};
	/**
	 * This method is invoked when a memory block conflict
	 * is detected. The start and end addresses of the conflict
	 * are passed into the method. To overwrite the conflict, return true.
	 * Otherwise return false to NOT overwrite the conflict.
	 * @param start the start address of the conflict
	 * @param end   the end   address of the conflict
	 * @return true to overwrite the conflict
	 */
	public boolean allowOverwrite(Address start, Address end);
}
