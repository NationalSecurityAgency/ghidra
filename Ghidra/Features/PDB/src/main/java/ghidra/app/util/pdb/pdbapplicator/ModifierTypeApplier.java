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
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractModifierMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractModifierMsType} types.
 */
public class ModifierTypeApplier extends MsDataTypeApplier {

	// Intended for: AbstractModifierMsType
	/**
	 * Constructor for modifier type applier
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 */
	public ModifierTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	@Override
	boolean apply(AbstractMsType type) throws PdbException, CancelledException {

		AbstractModifierMsType modifierMsType = (AbstractModifierMsType) type;
		// Doing pre-check on type first using the getDataTypeOrSchedule method.  The logic is
		//  simpler here for Composites or Functions because we only have one dependency type,
		//  so we are not doing a separate call to a pre-check method as there is in those appliers.
		//  If type is not available, return false.
		RecordNumber modifiedRecordNumber = modifierMsType.getModifiedRecordNumber();
		DataType modifiedType = applicator.getDataTypeOrSchedule(modifiedRecordNumber);
		if (modifiedType == null) {
			return false;
		}

		// If Ghidra eventually has a modified type (const, volatile) in its model, then we can
		//  perform the applicator.getDataType(modifierType) here, and the
		//  applicator.put(modifierType,dataType) before the return.
		// Obviously, we would also need to process and apply the modifier attributes.

		// If ghidra has modified types in the future, we will likely not perform a pass-through
		//  of the underlying type.  We might actually need to do a fixup or be able to pass the
		//  cycle-break information to a pointer or handle cycle-break information information
		//  in this modifier type.  Lots of things to consider.  Would we want to create a typedef
		//  for modifier type as a short-gap solution??? Not sure.

		// Note:
		// Pointers normally have their own modifiers, so would not necessarily expect to see
		//  the underlying type of a Modifier to be a pointer.  However, MSFT primitives include
		//  pointers to primitives, so in these cases we could see a const pointer to primitive
		//  where the const comes from the Modifier type.
		DataType modifierType = modifiedType;

		// Store modified type as modifier type
		applicator.putDataType(modifierMsType, modifierType);
		// I'm hesitant to schedule resolve... what if I'm a pointer.  Should I resolve
		//  modified pointers, modified other types, both, or neither?  TODO; investigate

		return true;
	}

}
