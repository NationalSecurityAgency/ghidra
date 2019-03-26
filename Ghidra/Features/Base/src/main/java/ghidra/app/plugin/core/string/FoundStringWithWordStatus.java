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
package ghidra.app.plugin.core.string;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.util.string.FoundString;

public class FoundStringWithWordStatus extends FoundString {

	private volatile boolean isHighConfidenceWord;

	public FoundStringWithWordStatus(FoundString source) {
		this(source.getAddress(), source.getLength(), source.getDataType(),
			source.getDefinedState());
	}

	public FoundStringWithWordStatus(Address address, int length, DataType stringDataType) {
		super(address, length, stringDataType);
		isHighConfidenceWord = false;
	}

	public FoundStringWithWordStatus(Address address, int length, DataType stringDataType,
			DefinedState definedState) {
		super(address, length, stringDataType, definedState);
		isHighConfidenceWord = false;
	}

	public FoundStringWithWordStatus(Address address, int length, DataType stringDataType,
			boolean isWord) {
		super(address, length, stringDataType);
		isHighConfidenceWord = isWord;
	}

	public FoundStringWithWordStatus(Address address, int length, DataType stringDataType,
			DefinedState definedState, boolean isWord) {
		super(address, length, stringDataType, definedState);
		isHighConfidenceWord = isWord;
	}

	public boolean isHighConfidenceWord() {
		return isHighConfidenceWord;
	}

	public void setIsHighConfidenceWord(boolean isWord) {
		isHighConfidenceWord = isWord;
	}

	@Override
	public String toString() {
		return super.toString() + ", high confidence=" + isHighConfidenceWord;
	}
}
