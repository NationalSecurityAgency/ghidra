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
package ghidra.trace.model.modules;

import java.util.Collection;
import java.util.Set;

public class TraceConflictedMappingException extends RuntimeException {
	private final Set<TraceStaticMapping> conflicts;

	public TraceConflictedMappingException(String message,
			Collection<TraceStaticMapping> conflicts) {
		super(message + ": " + conflicts);
		this.conflicts = Set.copyOf(conflicts);
	}

	public Set<TraceStaticMapping> getConflicts() {
		return conflicts;
	}
}
