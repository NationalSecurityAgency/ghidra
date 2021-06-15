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
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMemberMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.ClassFieldMsAttributes;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractMemberMsType} types.
 */
public class MemberTypeApplier extends MsTypeApplier {

	/**
	 * Constructor for member type applier.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractMemberMsType} to process.
	 */
	public MemberTypeApplier(PdbApplicator applicator, AbstractMemberMsType msType) {
		super(applicator, msType);
	}

	@Override
	BigInteger getSize() {
		return BigInteger.ZERO;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		dataType = applyMemberMsType((AbstractMemberMsType) msType);
//		DataType dataType = applyMemberMsType((AbstractMemberMsType) msType);
//		ghDataType = dataType; // temporary while below is commented-out
		// TODO: uncomment when above method not returning null
//		ghDataTypeDB = applicator.resolve(dataType);
	}

	String getName() {
		return ((AbstractMemberMsType) msType).getName();
	}

	BigInteger getOffset() {
		return ((AbstractMemberMsType) msType).getOffset();
	}

	ClassFieldMsAttributes getAttribute() {
		return ((AbstractMemberMsType) msType).getAttribute();
	}

	MsTypeApplier getFieldTypeApplier() {
		return applicator.getTypeApplier(
			((AbstractMemberMsType) msType).getFieldTypeRecordNumber());
	}

	private DataType applyMemberMsType(AbstractMemberMsType type) {

//		String memberName = type.getName();
//		BigInteger memberOffset = type.getOffset();
//		ClassFieldMsAttributes memberAttributes = type.getAttribute();
//		int fieldTypeIndex = type.getFieldTypeRecordIndex();
//
//		AbstractMsTypeApplier fieldTypeApplier = applicator.getTypeApplier(fieldTypeIndex);
//
//		DataType fieldDataType = fieldTypeApplier.getDataType();
//
////		DataType fieldDataType = getConvertedDataType(applicator, fieldTypeIndex);

		return null;
	}

}
