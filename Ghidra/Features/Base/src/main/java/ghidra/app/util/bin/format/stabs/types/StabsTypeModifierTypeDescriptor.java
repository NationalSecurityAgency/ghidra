package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.program.model.data.DataType;

/**
 * Type Descriptor which is a reference to a previously parsed type descriptor
 */
public final class StabsTypeModifierTypeDescriptor extends AbstractStabsTypeReferenceTypeDescriptor {

	/** Potential Modifier Types */
	public enum ModifierType {
		/** const */
		CONST,
		/** volatile */
		VOLATILE,
		/** space (Pascal) */
		SPACE
	}

	private final StabsTypeDescriptor subType;
	private final ModifierType type;

	/**
	 * Constructs a new StabsTypeReferenceTypeDescriptor
	 * @param symbol the token this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if this descriptor or what it references is invalid
	 */
	StabsTypeModifierTypeDescriptor(StabsSymbolDescriptor symbol, String stab) throws StabsParseException {
		super(symbol, stab);
		this.type = doGetModifierType();
		this.subType = doGetSubType();
	}

	private ModifierType doGetModifierType() throws StabsParseException {
		switch (stab.charAt(0)) {
			case 'k':
				return ModifierType.CONST;
			case 'B':
				return ModifierType.VOLATILE;
			case 'b':
				return ModifierType.SPACE;
			default:
				throw new StabsParseException(symbol.getName(), stab);
		}
	}

	@Override
	public DataType getDataType() {
		return subType.getDataType();
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.MISC;
	}

	@Override
	public int getLength() {
		return super.getLength()+1;
	}

	@Override
	public StabsTypeDescriptor getSubType() {
		return subType;
	}

	/**
	 * Gets this descriptors modifier type
	 * @return the modifier type
	 */
	public ModifierType getModifierType() {
		return type;
	}
}
