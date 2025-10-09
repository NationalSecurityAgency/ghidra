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
package ghidra.app.util;

import java.util.*;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.datastruct.LRUSet;

/**
 * Static class for remember the last few namespaces used for a program.
 */
public class NamespaceCache {
	public static final int MAX_RECENTS = 10;
	private static Map<Program, LRUSet<Namespace>> recentNamespaces = new HashMap<>();

	/**
	 * Returns the list of recently used namespaces for the given program.
	 * @param program the program to get namespaces for
	 * @return the list of recently used namespaces for the given program
	 */
	public static List<Namespace> get(Program program) {
		LRUSet<Namespace> recents = recentNamespaces.get(program);
		return recents != null ? recents.toList() : Collections.emptyList();
	}

	/**
	 * Adds a recently used namespace for a program.
	 * @param program the program to add a recently namespace
	 * @param namespace the recently used namespace to remember
	 */
	public static void add(Program program, Namespace namespace) {
		// no need to cache global namespace, it is always available
		if (namespace.isGlobal()) {
			return;
		}
		LRUSet<Namespace> recents = recentNamespaces.get(program);
		if (recents == null) {
			recents = new LRUSet<Namespace>(MAX_RECENTS);
			recentNamespaces.put(program, recents);
			program.addCloseListener(p -> recentNamespaces.remove(p));
		}
		recents.add(namespace);
	}
}
