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
package ghidra.lisa.pcode.locations;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import it.unive.lisa.program.cfg.CodeLocation;

public class InstLocation implements CodeLocation {

	private Function function;
	private Address addr;

	public InstLocation(Function function, Address addr) {
		this.function = function;
		this.addr = addr;
	}

	@Override
	public int compareTo(CodeLocation o) {
		if (o instanceof InstLocation i) {
			return addr.compareTo(i.addr);
		}
		return -1;
	}

	@Override
	public String getCodeLocation() {
		return addr.toString();
	}

	public Function function() {
		return function;
	}

	public Address getAddress() {
		return addr;
	}

}
