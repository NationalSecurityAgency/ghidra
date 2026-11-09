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
package ghidra.pcode.emu.linux;

import ghidra.pcode.exec.AccessPcodeExecutionException;
import ghidra.program.model.address.Address;

public class SegfaultPcodeExecutionException extends AccessPcodeExecutionException {
	private final Address address;
	private final int size;

	public SegfaultPcodeExecutionException(Address address, int size, String message) {
		this.address = address;
		this.size = size;
		super(message);
	}

	public Address getAddress() {
		return address;
	}

	public int getSize() {
		return size;
	}
}
