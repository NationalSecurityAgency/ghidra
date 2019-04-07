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
package ghidra.program.model;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class ReferenceManagerTestDouble implements ReferenceManager {

	@Override
	public Reference addReference(Reference reference) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addStackReference(Address fromAddr, int opIndex, int stackOffset,
			RefType type, SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addRegisterReference(Address fromAddr, int opIndex, Register register,
			RefType type, SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addMemoryReference(Address fromAddr, Address toAddr, RefType type,
			SourceType source, int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addOffsetMemReference(Address fromAddr, Address toAddr, long offset,
			RefType type, SourceType source, int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addShiftedMemReference(Address fromAddr, Address toAddr, int shiftValue,
			RefType type, SourceType source, int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addExternalReference(Address fromAddr, String libraryName, String extLabel,
			Address extAddr, SourceType source, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addExternalReference(Address fromAddr, Namespace extNamespace,
			String extLabel, Address extAddr, SourceType source, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addExternalReference(Address fromAddr, int opIndex, ExternalLocation location,
			SourceType source, RefType type) throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeAllReferencesFrom(Address beginAddr, Address endAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeAllReferencesFrom(Address fromAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getReferencesTo(Variable var) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Variable getReferencedVariable(Reference reference) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setPrimary(Reference ref, boolean isPrimary) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasFlowReferencesFrom(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getFlowReferencesFrom(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ReferenceIterator getExternalReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ReferenceIterator getReferencesTo(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ReferenceIterator getReferenceIterator(Address startAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference getReference(Address fromAddr, Address toAddr, int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getReferencesFrom(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getReferencesFrom(Address fromAddr, int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasReferencesFrom(Address fromAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasReferencesFrom(Address fromAddr, int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference getPrimaryReferenceFrom(Address addr, int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressIterator getReferenceSourceIterator(Address startAddr, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressIterator getReferenceSourceIterator(AddressSetView addrSet, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressIterator getReferenceDestinationIterator(Address startAddr, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressIterator getReferenceDestinationIterator(AddressSetView addrSet, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getReferenceCountTo(Address toAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getReferenceCountFrom(Address fromAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getReferenceDestinationCount() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getReferenceSourceCount() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasReferencesTo(Address toAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference updateRefType(Reference ref, RefType refType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setAssociation(Symbol s, Reference ref) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeAssociation(Reference ref) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void delete(Reference ref) {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte getReferenceLevel(Address toAddr) {
		throw new UnsupportedOperationException();
	}

}
