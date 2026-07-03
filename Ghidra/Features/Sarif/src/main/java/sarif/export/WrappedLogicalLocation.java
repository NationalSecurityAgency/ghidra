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
package sarif.export;

import ghidra.program.model.address.Address;

public class WrappedLogicalLocation {
	
	private ExtLogicalLocation lloc;
	private Address addr;
	private int index;

	public WrappedLogicalLocation(ExtLogicalLocation lloc, Address addr) {
		this.lloc = lloc;
		this.addr = addr;
	}

	public ExtLogicalLocation getLogicalLocation() {
		return lloc;
	}

	public Address getAddress() {
		return addr;
	}

	public int getIndex() {
		return index;
	}

	public void setIndex(int index) {
		this.index = index;
	}

}
