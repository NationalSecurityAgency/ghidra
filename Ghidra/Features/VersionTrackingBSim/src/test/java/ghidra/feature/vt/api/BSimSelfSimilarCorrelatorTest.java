/* ###
 * IP: GHIDRA
 * EXCLUDE: YES
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
package ghidra.feature.vt.api;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;

import org.junit.Test;

public class BSimSelfSimilarCorrelatorTest extends AbstractSelfSimilarCorrelatorTest {
	public BSimSelfSimilarCorrelatorTest( ) {
		super();
	}

@Test
 public void testFlow() throws Exception {
		exerciseFunctionsForFactory(new BSimProgramCorrelatorFactory(),
		// with default settings these three functions won't get matched
			getSourceMinus(0x010031ee, 0x01003ac0, 0x01004c1d));
	}

	private AddressSetView getSourceMinus(long... addresses) {
		AddressFactory addressFactory = sourceProgram.getAddressFactory();
		AddressSpace addressSpace = addressFactory.getDefaultAddressSpace();
		AddressSet set =
			new AddressSet(sourceProgram.getMemory().getInitializedAddressSet());
		for (long l : addresses) {
			Address address = addressSpace.getAddress(l);
			set = set.subtract(new AddressSet(address, address));
		}
		return set;
	}
}
