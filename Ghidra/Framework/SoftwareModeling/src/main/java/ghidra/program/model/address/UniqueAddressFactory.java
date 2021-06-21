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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.program.model.lang.Language;

public class UniqueAddressFactory {

	private AddressFactory addrFactory;
	private AddressSpace uniqueSpace;
	private final long firstAvailableOffset;
	private long nextOffset;

	public UniqueAddressFactory(AddressFactory addrFactory, Language language) {
		this.addrFactory = addrFactory;
		this.uniqueSpace = addrFactory.getUniqueSpace();
		if (language instanceof SleighLanguage) {
			firstAvailableOffset = ((SleighLanguage) language).getUniqueBase();
		}
		else {
			firstAvailableOffset = 0;
		}
		nextOffset = firstAvailableOffset;
	}

	public synchronized Address getNextUniqueAddress() {
		Address addr = uniqueSpace.getAddress(nextOffset);
		nextOffset += SleighBase.MAX_UNIQUE_SIZE;
		return addr;
	}

	public synchronized void reset() {
		nextOffset = firstAvailableOffset;
	}

	public AddressFactory getAddressFactory() {
		return addrFactory;
	}
}
