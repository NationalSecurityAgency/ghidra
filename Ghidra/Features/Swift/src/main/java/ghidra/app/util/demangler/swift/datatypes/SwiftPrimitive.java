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

import ghidra.app.util.demangler.DemangledDataType;

/**
 * A Swift primitive
 */
public class SwiftPrimitive extends DemangledDataType {

	/**
	 * Creates a new Swift primitive
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 * @param name The primitive name
	 */
	public SwiftPrimitive(String mangled, String originalDemangled, String name) {
		super(mangled, originalDemangled, name);
	}

	/**
	 * Creates a new Swift primitive
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 * @param name The primitive name
	 * @param unsigned True if the primitive should be unsigned; otherwise, false
	 */
	public SwiftPrimitive(String mangled, String originalDemangled, String name, boolean unsigned) {
		this(mangled, originalDemangled, name);
		setUnsigned();
	}
}
