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
package ghidra.app.plugin.core.debug.client.tracermi;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

public class DefaultMemoryMapper implements MemoryMapper {
	
	private final AddressFactory factory;

	public DefaultMemoryMapper(LanguageID id) {
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		try {
			Language lang = langServ.getLanguage(id);
			this.factory = lang.getAddressFactory();
		}
		catch (LanguageNotFoundException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Address map(Address address) {
		return address;
	}

	@Override
	public Address mapBack(Address address) {
		return address;
	}

	@Override
	public Address genAddr(String space, long offset) {
		return factory.getAddressSpace(space).getAddress(offset);
	}

}
