package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsTypeDescriptorType;
import ghidra.program.model.data.DataType;

/**
 * Reference and Pointer Type implementation of the StabTypeDescriptor
 */
public final class StabsReferenceTypeDescriptor extends AbstractStabsTypeDescriptor {

	/** Potential Reference Types */
	public enum ReferenceType {
		POINTER,
		REFERENCE,
		POINTER_TO_MEMBER
	}

	private final DataType dt;
	private final StabsTypeDescriptor subType;
	private final ReferenceType refType;

	/**
	 * Constructs a new StabsReferenceTypeDescriptor
	 * @param token the token this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if this descriptor or what it references is invalid
	 */
	StabsReferenceTypeDescriptor(StabsSymbolDescriptor token, String stab) throws StabsParseException {
		super(token, stab);
		this.refType = doGetRefType();
		this.subType = doGetSubType(stab);
		this.dt = doGetDataType();
	}

	private ReferenceType doGetRefType() throws StabsParseException {
		switch (stab.charAt(0)) {
			case '*':
				return ReferenceType.POINTER;
			case '&':
				return ReferenceType.REFERENCE;
			case '@':
				return ReferenceType.POINTER_TO_MEMBER;
			default:
				throw new StabsParseException(symbol.getName(), stab);
		}
	}

	private StabsTypeDescriptor doGetSubType(String stab) throws StabsParseException {
		String def = stab.substring(1);
		// this is recursive
		return StabsTypeDescriptorFactory.getTypeDescriptor(symbol, def);
	}

	private DataType doGetDataType() {
		return dtm.getPointer(subType.getDataType(), -1);
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.REFERENCE;
	}

	@Override
	public int getLength() {
		return subType.getLength()+1;
	}

	/**
	 * Gets the reference type
	 * @return the reference type
	 */
	public ReferenceType getReferenceType() {
		return refType;
	}
}
