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
package ghidra.app.util.bin.format.dwarf4.next;

import java.util.*;

/**
 * Helper for allocating unique string names.
 * <p>
 * "Reserved names" are names that will be used by later calls to the de-duper.
 * <p>
 * "Used names" are names that are already allocated and are in use.
 * <p>
 * Reserved names only prevent re-use of a name when a name is being generated because of a
 * collision with a "used name".   
 */
public class NameDeduper {
	private final Set<String> usedNames = new HashSet<>();
	private final Set<String> reservedNames = new HashSet<>();

	/**
	 * Create a new name de-duper.
	 * 
	 */
	public NameDeduper() {
		// empty
	}

	/**
	 * Add names to the the de-duper that have already been used.
	 *  
	 * @param alreadyUsedNames
	 */
	public void addUsedNames(Collection<String> alreadyUsedNames) {
		usedNames.addAll(alreadyUsedNames);
	}

	/**
	 * Add names to the de-duper that will be used in a future call.  These names do not block
	 * calls to confirm that a name is unique, but instead prevent the name from being used
	 * when an auto-generated name is created.
	 * 
	 * @param additionalReservedNames
	 */
	public void addReservedNames(Collection<String> additionalReservedNames) {
		reservedNames.addAll(additionalReservedNames);
	}

	/**
	 * Returns true if the specified name hasn't been allocated yet.
	 * 
	 * @param name
	 * @return
	 */
	public boolean isUniqueName(String name) {
		return name == null || !usedNames.contains(name);
	}

	/**
	 * Confirms that the specified name is unique, or returns a generated name that is unique.
	 * 
	 * @param name name to test
	 * @return {@code null} if specified name is already unique (and marks the specified name as
	 * used), or returns a new, unique generated name
	 */
	public String getUniqueName(String name) {
		if (name == null || usedNames.add(name)) {
			return null;
		}

		String original = name;
		int tryNum = 0;
		while (usedNames.contains(name) || reservedNames.contains(name)) {
			name = String.format("%s_%d", original, ++tryNum);
		}
		usedNames.add(name);
		return name;
	}

}
