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
public class ModifierTypeApplier extends MsTypeApplier {

	// Intended for: AbstractModifierMsType
	/**
	 * Constructor for modifier type applier.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 */
	public ModifierTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	RecordNumber getUnderlyingNonModifierRecordNumber(RecordNumber underlyingRecord) {
		return getUnderlyingNonModifierRecordNumber(applicator, underlyingRecord);
	}

	static RecordNumber getUnderlyingNonModifierRecordNumber(DefaultPdbApplicator applicator,
			RecordNumber underlyingRecord) {
		AbstractMsType underlyingType = applicator.getPdb().getTypeRecord(underlyingRecord);
		while (underlyingType instanceof AbstractModifierMsType modifierType) {
			RecordNumber modifiedRecord = modifierType.getModifiedRecordNumber();
			underlyingType = applicator.getPdb().getTypeRecord(modifiedRecord);
		}
		return underlyingType.getRecordNumber();
	}

	@Override
	DataType apply(AbstractMsType type, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		AbstractModifierMsType modifierType = (AbstractModifierMsType) type;
		RecordNumber modifiedRecord = modifierType.getModifiedRecordNumber();

		DataType modifiedType =
			applicator.getProcessedDataType(modifiedRecord, fixupContext, false);

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

//		if (modifiedType != null && !applicator.isPlaceholderType(modifiedType)) {
		if (modifiedType != null) {
			applicator.putDataType(modifierType, modifiedType);
		}
		return modifiedType;
	}
}
