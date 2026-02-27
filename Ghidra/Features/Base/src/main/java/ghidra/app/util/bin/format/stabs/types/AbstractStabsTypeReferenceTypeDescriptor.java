package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsTypeNumber;

/**
 * Type Descriptor which is a reference to a previously parsed type descriptor
 */
abstract class AbstractStabsTypeReferenceTypeDescriptor extends AbstractStabsTypeDescriptor {

	protected final StabsTypeNumber typeNumber;

	/**
	 * Constructs a new AbstractStabTypeReferenceTypeDescriptor
	 * @param token the token this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if this descriptor or what it references is invalid
	 */
	AbstractStabsTypeReferenceTypeDescriptor(StabsSymbolDescriptor token, String stab) {
		super(token, stab);
		this.typeNumber = new StabsTypeNumber(stab);
	}

	/**
	 * Gets the referenced type descriptor
	 * @return the referenced type descriptor
	 */
	public abstract StabsTypeDescriptor getSubType();

	protected boolean isDeclaration() {
		int index = stab.indexOf(typeNumber.toString());
		int length = typeNumber.toString().length();
		if (stab.length() > index+length) {
			return stab.charAt(index+length) == '=';
		}
		return false;
	}

	protected StabsTypeDescriptor doGetSubType() throws StabsParseException {
		int index = stab.indexOf(typeNumber.toString());
		int length = typeNumber.toString().length();
		if (isDeclaration()) {
			String subStab = stab.substring(index+length+1);
			file.addType(this, typeNumber);
			return StabsTypeDescriptorFactory.getTypeDescriptor(symbol, subStab);
		}
		return file.getType(typeNumber);
	}

	@Override
	public int getLength() {
		int length = typeNumber.toString().length();
		if (isDeclaration()) {
			return getSubType().getLength()+length+1;
		}
		return length;
	}
}
