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
package ghidra.app.util.bin.format.dwarf.expression;

import ghidra.program.model.pcode.Varnode;

public class DWARFExpressionValueException extends DWARFExpressionException {
	
	private Varnode vn;

	public DWARFExpressionValueException(Varnode vn) {
		super("Unable to access value of %s".formatted(vn));
		this.vn = vn;
	}

	public Varnode getVarnode() {
		return vn;
	}
}
