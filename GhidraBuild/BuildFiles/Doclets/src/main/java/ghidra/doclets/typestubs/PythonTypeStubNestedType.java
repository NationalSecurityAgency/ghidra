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
package ghidra.doclets.typestubs;

import java.io.PrintWriter;

import javax.lang.model.element.TypeElement;

/**
 * {@link PythonTypeStubElement} for a nested type
 */
final class PythonTypeStubNestedType extends PythonTypeStubType {

	// while it is possible to create a pseudo sub module to
	// make static nested classes and enum values individually
	// importable during type checking, it's not worth the effort

	/**
	 * Creates a new {@link PythonTypeStubNestedType}
	 *
	 * @param pkg the package containing this type
	 * @param el the element for this type
	 */
	PythonTypeStubNestedType(PythonTypeStubPackage pkg, TypeElement el) {
		super(pkg, el);
	}

	@Override
	void process(PrintWriter printer, String indent) {
		printClass(printer, indent);
	}
}
