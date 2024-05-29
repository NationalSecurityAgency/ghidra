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

import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;

/**
 * Applier for {@link AbstractVirtualFunctionTablePointerMsType} and
 * {@link AbstractVirtualFunctionTablePointerWithOffsetMsType} types.
 */
public class VirtualFunctionTablePointerTypeApplier extends MsDataTypeComponentApplier {

	// Intended for: AbstractVirtualFunctionTablePointerMsType or
	//  AbstractVirtualFunctionTablePointerWithOffsetMsType
	/**
	 * Constructor for enum type applier, for transforming a enum into a Ghidra DataType
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public VirtualFunctionTablePointerTypeApplier(DefaultPdbApplicator applicator)
			throws IllegalArgumentException {
		super(applicator);
	}

	int getOffset(AbstractMsType type) {
		if (type instanceof AbstractVirtualFunctionTablePointerWithOffsetMsType offType) {
			return offType.getOffset();
		}
		return 0;
	}

	/**
	 * Returns the name to use.
	 * @param type the PDB type being inspected
	 * @return Name of the pointer type.
	 */
	String getMemberName(AbstractMsType type) {
		return "VFTablePtr" + getOffset(type);
	}

	private static AbstractMsType validateType(AbstractMsType type)
			throws IllegalArgumentException {
		if (!(type instanceof AbstractVirtualFunctionTablePointerMsType vftPtrType)) {
			throw new IllegalArgumentException(
				"PDB Incorrectly applying " + type.getClass().getSimpleName() + " to " +
					VirtualFunctionTablePointerTypeApplier.class.getSimpleName());
		}
		return vftPtrType;
	}

}
