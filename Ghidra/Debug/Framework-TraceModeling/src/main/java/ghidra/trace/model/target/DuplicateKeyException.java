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
package ghidra.trace.model.target;

import ghidra.trace.model.target.TraceObject.ConflictResolution;

/**
 * Thrown when there are "duplicate keys" and the {@link ConflictResolution#DENY} strategy is passed
 * 
 * <p>
 * There are said to be "duplicate keys" when two value entries having the same parent and key have
 * overlapping lifespans. Such would create the possibility of a non-uniquely-defined value for a
 * given path, and so it is not allowed.
 */
public class DuplicateKeyException extends RuntimeException {
	/**
	 * Notify of a given conflicting key
	 * 
	 * @param key the key in conflict
	 */
	public DuplicateKeyException(String key) {
		super(key);
	}
}
