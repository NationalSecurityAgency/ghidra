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

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractBaseClassMsType}, {@link AbstractVirtualBaseClassMsType}, and
 * {@link AbstractIndirectVirtualBaseClassMsType} types.
 */
public class BaseClassTypeApplier extends MsTypeApplier {

	// Intended for: AbstractBaseClassMsType, AbstractVirtualBaseClassMsType, or
	//  AbstractIndirectVirtualBaseClassMsType
	/**
	 * Constructor for base class applier.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public BaseClassTypeApplier(DefaultPdbApplicator applicator)
			throws IllegalArgumentException {
		super(applicator);
	}

	/**
	 * Returns the record number of the base class
	 * @param type the PDB type being inspected
	 * @return the record number
	 */
	RecordNumber getBaseClassRecordNumber(AbstractMsType type) {
		if (type instanceof AbstractBaseClassMsType baseType) {
			return baseType.getBaseClassRecordNumber();
		}
		else if (type instanceof AbstractVirtualBaseClassMsType virtualType) {
			return virtualType.getBaseClassRecordNumber();
		}
		return ((AbstractIndirectVirtualBaseClassMsType) type).getBaseClassRecordNumber();
	}

	@Override
	DataType apply(AbstractMsType type, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		// do nothing
		return null;
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
