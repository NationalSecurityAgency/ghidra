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

import ghidra.app.util.bin.format.pdb.PdbBitField;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractBitfieldMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractBitfieldMsType} types.
 */
public class BitfieldTypeApplier extends AbstractMsTypeApplier {
	private AbstractMsTypeApplier elementTypeApplier = null;

	private static AbstractMsType validateType(AbstractMsType type)
			throws IllegalArgumentException {
		if (!(type instanceof AbstractBitfieldMsType)) {
			throw new IllegalArgumentException(
				"PDB Incorrectly applying " + type.getClass().getSimpleName() + " to " +
					BitfieldTypeApplier.class.getSimpleName());
		}
		return type;
	}

	/**
	 * Constructor for bitfield applier.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractBitfieldMsType} to processes
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public BitfieldTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		super(applicator, validateType(msType));
	}

	@Override
	public BigInteger getSize() {
		if (elementTypeApplier == null) {
			return BigInteger.ZERO;
		}
		return elementTypeApplier.getSize();
	}

	@Override
	public void apply() throws PdbException, CancelledException {
		// The bitfield does not get resolved/commited to the DataTypeManager.
		dataType = applyBitfieldMsType((AbstractBitfieldMsType) msType);
	}

	private DataType applyBitfieldMsType(AbstractBitfieldMsType type) {
		elementTypeApplier = applicator.getTypeApplier(type.getElementRecordNumber());
		if (elementTypeApplier instanceof ModifierTypeApplier) {
			elementTypeApplier =
				((ModifierTypeApplier) elementTypeApplier).getModifiedTypeApplier();
		}
		if (!(elementTypeApplier instanceof PrimitiveTypeApplier ||
			(elementTypeApplier instanceof EnumTypeApplier))) {
			applicator.appendLogMsg(
				"Unable to process underlying type for Bitfield: " + type.getName());
			return null;
		}
		DataType baseDataType = elementTypeApplier.getDataType();

		DataType bitFieldDataType = null;
		try {
			bitFieldDataType = new Pdb2BitField(baseDataType.clone(applicator.getDataTypeManager()),
				type.getBitLength(), type.getBitPosition());
		}
		catch (InvalidDataTypeException e) {
			applicator.appendLogMsg(
				"Problem creating PdbBitField for " + type.getName() + ", error: " + e.toString());
			return null;
		}
		return bitFieldDataType;
	}

	@Override
	public void resolve() {
		// Do not resolve Bitfield Types... will be resolved with composite!!!
	}

	/**
	 * <code>Pdb2BitField</code> provides ability to hang onto bitfield as a datatype.
	 * This will be transformed to a normal BitFieldDataType when cloned.
	 */
	private class Pdb2BitField extends PdbBitField {
		private Pdb2BitField(DataType baseDataType, int bitSize, int bitOffsetWithinBaseType)
				throws InvalidDataTypeException {
			super(baseDataType, bitSize, bitOffsetWithinBaseType);
		}
	}

}
