package ghidra.app.util.bin.format.stabs;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory;
import ghidra.program.model.data.DataType;

/**
 * Fuction Parameter implementation of the StabSymbolDescriptor
 */
public final class StabsParameterSymbolDescriptor extends AbstractStabsSymbolDescriptor {

	/** Potential Parameter Types */
	public static enum ParameterType {
		/** Register Parameter */
		REGISTER,
		/** Stack Parameter */
		STACK,
		/** Return Parameter */
		RETURN
	}

	private final ParameterType paramType;
	private final StabsTypeDescriptor type;

	/**
	 * Constructs a new StabsParameterSymbolDescriptor
	 * @param stab the portion of the stab containing this descriptor
	 * @param file the file containing this descriptor
	 * @throws StabsParseException if the descriptor or one it relies on is invalid
	 */
	StabsParameterSymbolDescriptor(String stab, StabsFile file) throws StabsParseException {
		super(stab, file);
		this.paramType = getParameterType(descriptor);
		String typeString = stab.substring(name.length()+2);
		this.type = StabsTypeDescriptorFactory.getTypeDescriptor(this, typeString);
	}

	private ParameterType getParameterType(char c) throws StabsParseException {
		switch (c) {
			case 'a':
			case 'D':
			case 'i':
			case 'R':
			case 'P':
				return ParameterType.REGISTER;
			case 'p':
			case 'v':
				return ParameterType.STACK;
			case 'x':
				return ParameterType.RETURN;
			default:
				throw new StabsParseException(name, stab);
		}
	}

	@Override
	public DataType getDataType() {
		return type.getDataType();
	}

	/**
	 * @return the parameter type
	 */
	public ParameterType getParameterType() {
		return paramType;
	}

	@Override
	public StabsSymbolDescriptorType getSymbolDescriptorType() {
		return StabsSymbolDescriptorType.PARAMETER;
	}

	@Override
	public StabsTypeDescriptor getTypeInformation() {
		return type;
	}
}
