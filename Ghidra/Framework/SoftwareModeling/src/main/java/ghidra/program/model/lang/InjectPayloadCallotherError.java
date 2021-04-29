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
package ghidra.program.model.lang;

import ghidra.program.model.address.AddressFactory;

/**
 * A substitute for a callother fixup that did not fully parse
 */
public class InjectPayloadCallotherError extends InjectPayloadCallother {

	/**
	 * Constructor for use if the p-code template did not parse
	 * @param addrFactory is the address factory to use constructing dummy p-code
	 * @param failedPayload is the object with the failed template
	 */
	public InjectPayloadCallotherError(AddressFactory addrFactory,
			InjectPayloadCallother failedPayload) {
		super(InjectPayloadSleigh.getDummyPcode(addrFactory), failedPayload);
	}

	public InjectPayloadCallotherError(AddressFactory addrFactory, String nm) {
		super(InjectPayloadSleigh.getDummyPcode(addrFactory), nm);
	}

	@Override
	public boolean isErrorPlaceholder() {
		return true;
	}
}
