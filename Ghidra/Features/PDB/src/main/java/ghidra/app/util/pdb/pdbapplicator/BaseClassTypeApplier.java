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
package ghidra.app.util.pdb.pdbapplicator;

import java.math.BigInteger;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractBaseClassMsType}, {@link AbstractVirtualBaseClassMsType}, and
 * {@link AbstractIndirectVirtualBaseClassMsType} types.
 */
public class BaseClassTypeApplier extends MsTypeApplier {

	/**
	 * Constructor for base class applier.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractBaseClassMsType}, {@link AbstractVirtualBaseClassMsType}, or
	 * {@link AbstractIndirectVirtualBaseClassMsType} to processes.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public BaseClassTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		super(applicator, validateType(msType));
	}

	// The MsTypes for which we are working do not have a size in and of themselves, but the
	//  classes/structures to which they refer have a size, even if zero.
	// For here, we are only reporting what "we" have, not what the underlying sizes are.
	// ...and a value of zero is our "don't know" and "not represented" value.
	@Override
	BigInteger getSize() {
		return BigInteger.ZERO;
	}

	/**
	 * Returns the offset of the Base Class within the inheriting class.
	 * @return the offset.
	 * @throws PdbException if field is not available.
	 */
	BigInteger getOffset() throws PdbException {
		if (msType instanceof AbstractBaseClassMsType) {
			return ((AbstractBaseClassMsType) msType).getOffset();
		}
		throw new PdbException("Offset is not a valid field");
	}

	/**
	 * Returns the offset of the base base pointer within the class.
	 * @return the offset.
	 * @throws PdbException if field is not available.
	 */
	BigInteger getBasePointerOffset() throws PdbException {
		if (msType instanceof AbstractBaseClassMsType) {
			throw new PdbException("Base Pointer Offset is not valid field");
		}
		else if (msType instanceof AbstractVirtualBaseClassMsType) {
			return ((AbstractVirtualBaseClassMsType) msType).getBasePointerOffset();
		}
		return ((AbstractIndirectVirtualBaseClassMsType) msType).getBasePointerOffset();
	}

	/**
	 * Returns the attributes of the base class within the inheriting class.
	 * @return the attributes;
	 */
	ClassFieldMsAttributes getAttributes() {
		if (msType instanceof AbstractBaseClassMsType) {
			return ((AbstractBaseClassMsType) msType).getAttributes();
		}
		else if (msType instanceof AbstractVirtualBaseClassMsType) {
			return ((AbstractVirtualBaseClassMsType) msType).getAttributes();
		}
		return ((AbstractIndirectVirtualBaseClassMsType) msType).getAttributes();
	}

	/**
	 * Returns the record number of the base class.
	 * @return the record number;
	 */
	RecordNumber getBaseClassRecordNumber() {
		if (msType instanceof AbstractBaseClassMsType) {
			return ((AbstractBaseClassMsType) msType).getBaseClassRecordNumber();
		}
		else if (msType instanceof AbstractVirtualBaseClassMsType) {
			return ((AbstractVirtualBaseClassMsType) msType).getBaseClassRecordNumber();
		}
		return ((AbstractIndirectVirtualBaseClassMsType) msType).getBaseClassRecordNumber();
	}

	/**
	 * Returns whether there is a Virtual Base Pointer type index available.
	 * @return {@code true} if available.
	 */
	boolean hasVirtualBasePointerTypeIndex() {
		return (!(msType instanceof AbstractBaseClassMsType));
	}

	/**
	 * Returns the record number of the virtual base pointer.
	 * @return the record number;
	 * @throws PdbException if not a virtual base class.
	 */
	RecordNumber getVirtualBasePointerRecordNumber() throws PdbException {
		if (msType instanceof AbstractVirtualBaseClassMsType) {
			return ((AbstractVirtualBaseClassMsType) msType).getVirtualBasePointerRecordNumber();
		}
		else if (msType instanceof AbstractIndirectVirtualBaseClassMsType) {
			return ((AbstractIndirectVirtualBaseClassMsType) msType).getVirtualBasePointerRecordNumber();
		}
		throw new PdbException("Not a virtual base class");
	}

	@Override
	void apply() throws PdbException, CancelledException {
		// do nothing at the moment.
	}

	private static AbstractMsType validateType(AbstractMsType type)
			throws IllegalArgumentException {
		if (!(type instanceof AbstractBaseClassMsType) &&
			!(type instanceof AbstractVirtualBaseClassMsType) &&
			!(type instanceof AbstractIndirectVirtualBaseClassMsType)) {
			throw new IllegalArgumentException(
				"PDB Incorrectly applying " + type.getClass().getSimpleName() + " to " +
					BaseClassTypeApplier.class.getSimpleName());
		}
		return type;
	}

}
