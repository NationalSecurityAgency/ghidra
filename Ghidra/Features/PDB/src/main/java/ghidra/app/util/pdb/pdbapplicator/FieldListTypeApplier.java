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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;

/**
 * Applier for {@link AbstractFieldListMsType} types and {@code NO_TYPE} when in place of the
 * former type.
 */
public class FieldListTypeApplier extends MsDataTypeComponentApplier {

	//TODO: evaluate the static method and multiple constructors... what can be cleaned up with
	// regard to these and the possible NoType record???
	static FieldListTypeApplier getFieldListApplierSpecial(DefaultPdbApplicator applicator,
			RecordNumber recordNumber) throws PdbException {
		if (recordNumber.isNoType()) {
			// We can use any Field List MS type, as they use the same applier
			return (FieldListTypeApplier) applicator.getTypeApplier(FieldListMsType.PDB_ID);
		}
		MsTypeApplier applier = applicator.getTypeApplier(recordNumber);
		if (applier instanceof FieldListTypeApplier fieldListApplier) {
			return fieldListApplier;
		}
		throw new PdbException("Problem creating field list");
	}

	/**
	 * Constructor
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 * @throws IllegalArgumentException Upon invalid arguments
	 */
	public FieldListTypeApplier(DefaultPdbApplicator applicator) throws IllegalArgumentException {
		super(applicator);
	}

	//==============================================================================================

	record FieldLists(List<AbstractMsType> bases, List<AbstractMsType> members,
			List<AbstractMemberMsType> nonstaticMembers,
			List<AbstractStaticMemberMsType> staticMembers,
			List<AbstractVirtualFunctionTablePointerMsType> vftPtrs, List<AbstractMsType> methods,
			List<AbstractNestedTypeMsType> nestedTypes, List<AbstractEnumerateMsType> enumerates) {}

	//==============================================================================================

	FieldLists getFieldLists(RecordNumber recordNumber) throws PdbException {
		AbstractMsType type = applicator.getTypeRecord(recordNumber);
		if (type instanceof PrimitiveMsType primitive && primitive.isNoType()) {
			return new FieldLists(new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
				new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
				new ArrayList<>());
		}
		else if (type instanceof AbstractFieldListMsType fieldListType) {
			return getFieldLists(fieldListType);
		}
		throw new PdbException(type.getClass().getSimpleName() + " seen where " +
			FieldListMsType.class.getSimpleName() + " expected for record number " + recordNumber);
	}

	FieldLists getFieldLists(AbstractFieldListMsType fieldListType) throws PdbException {
		List<AbstractMsType> bases = new ArrayList<>();
		List<AbstractMsType> members = new ArrayList<>();
		List<AbstractMsType> methods = new ArrayList<>();
		for (MsTypeField typeIterated : fieldListType.getBaseClassList()) {
			bases.add((AbstractMsType) typeIterated);
		}
		for (MsTypeField typeIterated : fieldListType.getMemberList()) {
			members.add((AbstractMsType) typeIterated);
		}
		for (MsTypeField typeIterated : fieldListType.getMethodList()) {
			methods.add((AbstractMsType) typeIterated);
		}
		List<AbstractMemberMsType> nonstaticMembers =
			new ArrayList<>(fieldListType.getNonStaticMembers());
		List<AbstractStaticMemberMsType> staticMembers =
			new ArrayList<>(fieldListType.getStaticMembers());
		List<AbstractVirtualFunctionTablePointerMsType> vftPtrs =
			new ArrayList<>(fieldListType.getVftPointers());
		List<AbstractNestedTypeMsType> nestedTypes =
			new ArrayList<>(fieldListType.getNestedTypes());
		List<AbstractEnumerateMsType> enumerates = new ArrayList<>(fieldListType.getEnumerates());

		for (AbstractIndexMsType indexType : fieldListType.getIndexList()) {
			RecordNumber subRecordNumber = indexType.getReferencedRecordNumber();
			MsTypeApplier referencedTypeApplier =
				applicator.getTypeApplier(indexType.getReferencedRecordNumber());
			if (referencedTypeApplier instanceof FieldListTypeApplier fieldListApplier) {
				FieldListTypeApplier.FieldLists lists =
					fieldListApplier.getFieldLists(subRecordNumber);
				bases.addAll(lists.bases());
				members.addAll(lists.members());
				methods.addAll(lists.methods());
				nonstaticMembers.addAll(lists.nonstaticMembers());
				staticMembers.addAll(lists.staticMembers());
				vftPtrs.addAll(lists.vftPtrs());
				nestedTypes.addAll(lists.nestedTypes());
				enumerates.addAll(lists.enumerates());
			}
			else {
				pdbLogAndInfoMessage(this, "referenceTypeApplier is not FieldListTypeApplier");
			}
		}

		return new FieldLists(bases, members, nonstaticMembers, staticMembers, vftPtrs, methods,
			nestedTypes,
			enumerates);
	}

}
