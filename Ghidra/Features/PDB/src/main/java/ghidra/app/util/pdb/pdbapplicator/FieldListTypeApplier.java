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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractFieldListMsType} types and {@code NO_TYPE} when in place of the
 * former type.
 */
public class FieldListTypeApplier extends MsTypeApplier {

	private List<MsTypeApplier> baseClassList = new ArrayList<>();
	private List<MsTypeApplier> memberList = new ArrayList<>();
	private List<MsTypeApplier> methodList = new ArrayList<>();
	private boolean isEmpty;

	// return can be null
	static FieldListTypeApplier getFieldListApplierSpecial(PdbApplicator applicator,
			RecordNumber recordNumber) throws PdbException {
		MsTypeApplier applier =
			applicator.getApplierOrNoTypeSpec(recordNumber, FieldListTypeApplier.class);
		FieldListTypeApplier fieldListApplier = null;
		if (applier instanceof FieldListTypeApplier) {
			return (FieldListTypeApplier) applicator.getApplierOrNoTypeSpec(recordNumber,
				FieldListTypeApplier.class);
		}
		try {
			if (recordNumber.getCategory() == RecordCategory.TYPE) {
				fieldListApplier = new FieldListTypeApplier(applicator,
					applicator.getPdb().getTypeRecord(recordNumber), true);
			}
		}
		catch (IllegalArgumentException e) {
			applicator.appendLogMsg(e.getMessage());
		}
		return fieldListApplier;
	}

	/**
	 * Constructor.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractFieldListMsType} or {@link PrimitiveMsType} of {@code NO_TYPE}
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public FieldListTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		this(applicator, msType, false);
	}

	/**
	 * Constructor with override for NO_TYPE Primitive.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractFieldListMsType} or {@link PrimitiveMsType} of {@code NO_TYPE}
	 * @param noType {@code true} to specify that {@code msType} is NO_TYPE.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public FieldListTypeApplier(PdbApplicator applicator, AbstractMsType msType, boolean noType)
			throws IllegalArgumentException {
		super(applicator, msType);
		if (noType && msType instanceof PrimitiveMsType && ((PrimitiveMsType) msType).isNoType()) {
			this.isEmpty = true;
		}
		else {
			if (!(msType instanceof AbstractFieldListMsType)) {
				throw new IllegalArgumentException("PDB Incorrectly applying " +
					msType.getClass().getSimpleName() + " to " + this.getClass().getSimpleName());
			}
			this.isEmpty = false;
		}
	}

	/**
	 * Indicates that the list is empty
	 * @return {@code true} if list is empty.
	 */
	boolean isEmpty() {
		return isEmpty;
	}

	@Override
	BigInteger getSize() {
		return BigInteger.ZERO;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		dataType = applyFieldListMsType((AbstractFieldListMsType) msType);
	}

	List<MsTypeApplier> getBaseClassList() {
		return baseClassList;
	}

	List<MsTypeApplier> getMemberList() {
		return memberList;
	}

	List<MsTypeApplier> getMethodList() {
		return methodList;
	}

	private DataType applyFieldListMsType(AbstractFieldListMsType type)
			throws PdbException, CancelledException {

		applyBaseClasses(type.getBaseClassList());
		applyMembers(type.getMemberList());
		applyMethods(type.getMethodList());

		for (AbstractIndexMsType indexType : type.getIndexList()) {
			MsTypeApplier referencedTypeApplier =
				applicator.getTypeApplier(indexType.getReferencedRecordNumber());
			if (referencedTypeApplier instanceof FieldListTypeApplier) {
				FieldListTypeApplier subApplier = (FieldListTypeApplier) referencedTypeApplier;
				baseClassList.addAll(subApplier.getBaseClassList());
				memberList.addAll(subApplier.getMemberList());
				methodList.addAll(subApplier.getMethodList());
			}
			else {
				pdbLogAndInfoMessage(this, "referenceTypeApplier is not FieldListTypeApplier");
			}
		}
		return null;
	}

	private void applyBaseClasses(List<MsTypeField> baseClasses)
			throws CancelledException, PdbException {
		for (MsTypeField typeIterated : baseClasses) {
			// Use dummy index of zero. 
			MsTypeApplier applier =
				applicator.getTypeApplier((AbstractMsType) typeIterated);
			applier.apply(); // Need to apply here, as these are embedded records
			baseClassList.add(applier);
		}
	}

	private void applyMembers(List<MsTypeField> members) throws CancelledException, PdbException {
		for (MsTypeField typeIterated : members) {
			// Use dummy index of zero.
			MsTypeApplier applier =
				applicator.getTypeApplier((AbstractMsType) typeIterated);
			applier.apply(); // Need to apply here, as these are embedded records
			memberList.add(applier);
		}
	}

	private void applyMethods(List<MsTypeField> methods) throws CancelledException, PdbException {
		for (MsTypeField typeIterated : methods) {
			// Use dummy index of zero.
			MsTypeApplier applier =
				applicator.getTypeApplier((AbstractMsType) typeIterated);
			// TODO: note that these are likely NoTypeAppliers at the moment, as we had not
			// yet implemented appliers for AbstractOneMethodMsType and
			//  AbstractOverloadedMethodMsType
			applier.apply(); // Need to apply here, as these are embedded records
			methodList.add(applier);
		}
	}

}
