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
package ghidra.app.util.demangler;

/**
 * A class to represent a demangled function indirect.  A function indirect is
 * similar to a function pointer or a function reference except that it does
 * not have the start (*) for a pointer or ampersand (&amp;) for a reference, but
 * is still an indirect definition (not a regular function definition).  The
 * function indirect is prevalent in the Microsoft model, if not other models.
 */
public class DemangledFunctionIndirect extends AbstractDemangledFunctionDefinitionDataType {

	public DemangledFunctionIndirect(String mangled, String originalDemangled) {
		super(mangled, originalDemangled);
	}

	@Override
	protected String getTypeString() {
		return EMPTY_STRING;
	}

	@Override
	protected void addFunctionPointerParens(StringBuilder buffer, String s) {
		// do not display pointer parens
		buffer.append(s);
	}
}
