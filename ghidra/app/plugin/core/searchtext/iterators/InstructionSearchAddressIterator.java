/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.searchtext.iterators;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.util.Iterator;

public class InstructionSearchAddressIterator implements AddressIterator {

	private InstructionIterator instructionIterator;

	public InstructionSearchAddressIterator(InstructionIterator instructionIterator) {
		this.instructionIterator = instructionIterator;
	}

	@Override
	public boolean hasNext() {
		return instructionIterator.hasNext();
	}

	@Override
	public Address next() {
		Instruction instruction = instructionIterator.next();
		return instruction.getAddress();
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}
}
