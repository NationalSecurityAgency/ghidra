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
package ghidra.feature.vt.api.stringable.deprecated;

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class LocalVariableStringable extends Stringable {

	public static final String SHORT_NAME = "LOCAL";

	private LocalVariableInfo localVariableInfo;

	public LocalVariableStringable() {
		super(SHORT_NAME);
	}

	public LocalVariableStringable(Variable localVariable) {
		super(SHORT_NAME);
		localVariableInfo = LocalVariableInfo.createLocalVariableInfo(localVariable);
	}

	@Override
	public String getDisplayString() {
		return localVariableInfo.getDataType().getName() + " " + localVariableInfo.getName();
	}

	@Override
	protected String doConvertToString(Program program) {
		return localVariableInfo.convertToString();
	}

	@Override
	protected void doRestoreFromString(String string, Program program) {
		localVariableInfo = LocalVariableInfo.createLocalVariableInfo(string, program);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = prime * ((localVariableInfo == null) ? 0 : localVariableInfo.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj)
			return true;
		if (getClass() != obj.getClass())
			return false;
		LocalVariableStringable other = (LocalVariableStringable) obj;
		if (localVariableInfo == null) {
			if (other.localVariableInfo != null)
				return false;
		}
		else if (!localVariableInfo.equals(other.localVariableInfo))
			return false;
		return true;
	}

	public Variable getLocalVariable(Function function, Address destinationStorageAddress) {
		return localVariableInfo.createLocalVariable(function, destinationStorageAddress);
	}
}
