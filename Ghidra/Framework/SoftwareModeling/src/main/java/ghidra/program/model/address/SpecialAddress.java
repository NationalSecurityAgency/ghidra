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
package ghidra.program.model.address;

/**
 * Class used to represent "special addresses"
 */
public class SpecialAddress extends GenericAddress {

	SpecialAddress(String name) {
		super(new GenericAddressSpace(name, 0, 1, AddressSpace.TYPE_NONE, -1), 0);
	}

	@Override
	public String toString() {
		return addrSpace.getName();
	}

	@Override
	public String toString(boolean showAddressSpace) {
		return addrSpace.getName();
	}

	@Override
	public String toString(String prefix) {
		return addrSpace.getName();
	}
}
