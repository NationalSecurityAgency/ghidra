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
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractArrayMsType;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractArrayMsType} types.
 */
public class ArrayTypeApplier extends MsTypeApplier {

	private MsTypeApplier underlyingTypeApplier = null;
	private boolean isFlexibleArray = false;

	/**
	 * Constructor for the applicator that applies a "array" type, transforming it into a
	 * Ghidra DataType.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractArrayMsType} to processes.
	 */
	public ArrayTypeApplier(PdbApplicator applicator, AbstractArrayMsType msType) {
		super(applicator, msType);
	}

	//==============================================================================================
	boolean isFlexibleArray() {
		return isFlexibleArray;
	}

	@Override
	void deferredApply() throws PdbException, CancelledException {
		// No work done here.  Just deferring resolve.
	}

	//==============================================================================================
	@Override
	BigInteger getSize() {
		return ((AbstractArrayMsType) msType).getSize();
	}

	@Override
	void apply() throws PdbException, CancelledException {
		applyOrDeferForDependencies();
	}

	private void applyOrDeferForDependencies() {
		AbstractArrayMsType type = (AbstractArrayMsType) msType;
		underlyingTypeApplier = applicator.getTypeApplier(type.getElementTypeRecordNumber());
		if (underlyingTypeApplier instanceof ModifierTypeApplier) {
			underlyingTypeApplier =
				((ModifierTypeApplier) underlyingTypeApplier).getModifiedTypeApplier();
		}
		underlyingTypeApplier = underlyingTypeApplier.getDependencyApplier();
		applyType(type); // applying now, but resolve() might get deferred.
	}

//	private void recurseAddDependency(AbstractMsTypeApplier dependee)
//			throws CancelledException, PdbException {
//		if (dependee instanceof ModifierTypeApplier) {
//			ModifierTypeApplier modifierApplier = (ModifierTypeApplier) dependee;
//			recurseAddDependency(modifierApplier.getModifiedTypeApplier());
//		}
//		else if (dependee instanceof CompositeTypeApplier) {
//			CompositeTypeApplier defApplier =
//				((CompositeTypeApplier) dependee).getDefinitionApplier();
//			if (defApplier != null) {
//				applicator.addApplierDependency(this, defApplier);
//			}
//			else {
//				applicator.addApplierDependency(this, dependee);
//			}
//			setDeferred();
//		}
//		else if (dependee instanceof ArrayTypeApplier) {
//			applicator.addApplierDependency(this, dependee);
//			setDeferred();
//		}
//		else if (dependee instanceof BitfieldTypeApplier) {
//			int x =
//				((AbstractBitfieldMsType) ((BitfieldTypeApplier) dependee).getMsType()).getElementTypeIndex();
//			AbstractMsTypeApplier underlyingApplier = applicator.getTypeApplier(x);
//			if (underlyingApplier instanceof EnumTypeApplier) {
//				applicator.addApplierDependency(this, underlyingApplier);
//				setDeferred();
//			}
//		}
//		//We are assuming that bitfields on typedefs will not be defined.
//	}
//

	private void applyType(AbstractArrayMsType type) {
		applyArrayMsType((AbstractArrayMsType) msType);
	}

	private void applyArrayMsType(AbstractArrayMsType type) {
		if (isApplied()) {
			return;
		}

		long longUnderlyingSize =
			PdbApplicator.bigIntegerToLong(applicator, underlyingTypeApplier.getSize());
		DataType underlyingDataType = underlyingTypeApplier.getDataType();

		if (longUnderlyingSize > Integer.MAX_VALUE) {
			String msg = "PDB " + type.getClass().getSimpleName() + ": Underlying type too large " +
				underlyingDataType.getName();
			Msg.warn(this, msg);
			underlyingDataType = Undefined1DataType.dataType;
			longUnderlyingSize = 1L;
		}
		else if (longUnderlyingSize == 0L) {
			String msg = "PDB " + type.getClass().getSimpleName() +
				": Zero-sized underlying type " + underlyingDataType.getName();
			Msg.warn(this, msg);
			underlyingDataType = Undefined1DataType.dataType;
			longUnderlyingSize = 1L;
		}

		long longArraySize = getSizeLong();
		long longNumElements = longArraySize / longUnderlyingSize;

		if (longNumElements > Integer.MAX_VALUE) {
			String msg = "PDB " + type.getClass().getSimpleName() +
				": Array num elements too large: " + longUnderlyingSize;
			Msg.warn(this, msg);
			longNumElements = 1L;
		}
		else if (longArraySize == 0) {
			//flexible array
			longNumElements = 0L;
		}
		else if (longArraySize % longUnderlyingSize != 0L) {
			String msg = "PDB " + type.getClass().getSimpleName() +
				": Array num elements calculation error underlying type " + longArraySize + " % " +
				longUnderlyingSize;
			Msg.warn(this, msg);
			// bad calculation.  Underlying type does not evenly fit into array total size.
			underlyingDataType = Undefined1DataType.dataType;
			longUnderlyingSize = 1L;
			longNumElements = longArraySize;
		}

		int numElements = (int) longNumElements;

		ArrayDataType arrayDataType;

		// TODO: Need to find way to pass errorComment on to encompassing composite or other
		if (numElements == 0) {
			// flexible array
			arrayDataType = new ArrayDataType(underlyingDataType, 1, underlyingDataType.getLength(),
				applicator.getDataTypeManager());
			isFlexibleArray = true;
		}
		else {
			arrayDataType = new ArrayDataType(underlyingDataType, numElements, -1,
				applicator.getDataTypeManager());
			isFlexibleArray = false;
		}

		setApplied();

		dataType = arrayDataType;
	}

}
