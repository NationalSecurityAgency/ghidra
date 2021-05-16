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
 * A substitute for a callfixup that did not successfully parse.
 */
public class InjectPayloadCallfixupError extends InjectPayloadCallfixup {

	public InjectPayloadCallfixupError(AddressFactory addrFactory,
			InjectPayloadCallfixup failedPayload) {
		// Make a partial clone
		super(InjectPayloadSleigh.getDummyPcode(addrFactory), failedPayload);
	}

	public InjectPayloadCallfixupError(AddressFactory addrFactory, String nm) {
		super(InjectPayloadSleigh.getDummyPcode(addrFactory), nm);
	}

	@Override
	public boolean isErrorPlaceholder() {
		return true;
	}
}
