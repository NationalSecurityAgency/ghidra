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
 * A class to represent a demangled function pointer
 */
public class DemangledFunctionPointer extends AbstractDemangledFunctionDefinitionDataType {

	/** display parens in front of parameter list */
	private boolean displayFunctionPointerSyntax = true;

	public DemangledFunctionPointer(String mangled, String originalDemangled) {
		super(mangled, originalDemangled);
		incrementPointerLevels(); // a function pointer is 1 level by default
	}

	@Override
	protected String getTypeString() {
		return "*";
	}

	/**
	 * Signals whether to display function pointer syntax when there is no function name, which 
	 * is '{@code (*)}', such as found in this example '{@code void (*)()}'.  the default is true
	 * @param b true to display nameless function pointer syntax; false to not display 
	 */
	public void setDisplayDefaultFunctionPointerSyntax(boolean b) {
		this.displayFunctionPointerSyntax = b;
	}

	@Override
	protected void addFunctionPointerParens(StringBuilder buffer, String s) {
		if (!displayFunctionPointerSyntax) {
			return;
		}

		buffer.append('(').append(s).append(')');
	}
}
