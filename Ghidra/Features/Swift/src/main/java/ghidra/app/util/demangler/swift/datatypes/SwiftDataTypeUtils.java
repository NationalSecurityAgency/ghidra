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
package ghidra.app.util.demangler.swift.datatypes;

import java.util.*;

import ghidra.app.util.demangler.*;
import ghidra.program.model.data.CategoryPath;

/**
 * Swift data type utilities
 */
public class SwiftDataTypeUtils {

	/**
	 * Default path to store Swift data structures in the data type manager
	 */
	public static final CategoryPath SWIFT_CATEGORY = new CategoryPath("/Demangler");

	/**
	 * Checks to see if the given namespace is the standard Swift namespace
	 * 
	 * @param namespace The namespace to check
	 * @return True if the given namespace is the standard Swift namespace; otherwise, false
	 */
	public static boolean isSwiftNamespace(Demangled namespace) {
		return namespace != null && namespace.getName().equals("Swift");
	}

	/**
	 * Gets a {@link Demangled} to represent the standard Swift namespace
	 * 
	 * @return A {@link Demangled} to represent the standard Swift namespace
	 */
	public static Demangled getSwiftNamespace() {
		return new DemangledUnknown("", "Swift", "Swift");
	}

	/**
	 * Gets a {@link CategoryPath} based on the given namespace
	 * 
	 * @param namespace The namespace
	 * @return A {@link CategoryPath} based on the given namespace
	 */
	public static CategoryPath getCategoryPath(Demangled namespace) {
		if (namespace == null) {
			return SWIFT_CATEGORY;
		}
		LinkedList<String> path = new LinkedList<>();
		while (namespace != null) {
			path.addFirst(namespace.getNamespaceName());
			namespace = namespace.getNamespace();
		}
		return new CategoryPath(SWIFT_CATEGORY, path);
	}

	/**
	 * Creates a {@link List} of {@link DemangledParameter parameters} found within the given
	 * {@link Demangled} object
	 *   
	 * @param demangled A {@link Demangled} object
	 * @return A {@link List} of {@link DemangledParameter parameters} found within the given
	 *   {@link Demangled} object
	 */
	public static List<DemangledParameter> extractParameters(Demangled demangled) {
		List<DemangledParameter> params = new ArrayList<>();
		if (demangled instanceof DemangledVariable variable) {
			demangled = variable.getDataType();
		}
		if (demangled instanceof DemangledList list) {
			for (Demangled d : list) {
				if (d instanceof DemangledDataType type) {
					params.add(new DemangledParameter(type));
				}
			}
		}
		else if (demangled instanceof DemangledDataType type) {
			params.add(new DemangledParameter(type));
		}
		return params;
	}
}
