package ghidra.app.util.bin.format.stabs;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory;
import ghidra.program.model.data.DataType;

/**
 * Variable implementation of the StabSymbolDescriptor
 */
public final class StabsVariableSymbolDescriptor extends AbstractStabsSymbolDescriptor {

	/** Potential Variable Types */
	public enum VariableType {
		/** Stack Variable */
		STACK,
		/** Global Variable */
		GLOBAL,
		/** Register Variable */
		REGISTER,
		/** Statically Allocated Block of Variables */
		COMMON_BLOCK,
		/** Static Variable */
		STATIC,
		/** Fortran Pointer Based Variable */
		BASED,
		/** Function Parameter */
		PARAMETER,
		/** Local Variable */
		LOCAL;
	}

	private final VariableType vType;
	private final StabsTypeDescriptor type;

	/**
	 * Constructs a new StabsVariableSymbolDescriptor
	 * @param stab the portion of the stab containing this descriptor
	 * @param file the file containing this descriptor
	 * @throws StabsParseException if the descriptor or one it relies on is invalid
	 */
	StabsVariableSymbolDescriptor(String stab, StabsFile file) throws StabsParseException {
		super(stab, file);
		this.vType = doGetVariableType();
		String typeStab;
		if (vType == VariableType.STACK) {
			typeStab = stab.substring(stab.indexOf(':')+1);
		} else {
			typeStab = stab.substring(stab.indexOf(':')+2);
		}
		this.type = StabsTypeDescriptorFactory.getTypeDescriptor(this, typeStab);
	}

	@Override
	public DataType getDataType() {
		return type.getDataType();
	}

	@Override
	public StabsSymbolDescriptorType getSymbolDescriptorType() {
		return StabsSymbolDescriptorType.VARIABLE;
	}

	private VariableType doGetVariableType() throws StabsParseException {
		switch (descriptor) {
			case '(':
			case '-':
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				return VariableType.STACK;
			case 'b':
				return VariableType.BASED;
			case 'd':
			case 'r':
				return VariableType.REGISTER;
			case 'G':
				return VariableType.GLOBAL;
			case 's':
				return VariableType.LOCAL;
			case 'S':
			case 'V':
				return VariableType.STATIC;
			default:
				throw new StabsParseException(name, stab);
		}
	}

	/**
	 * @return the variable type
	 */
	public VariableType getVariableType() {
		return vType;
	}
}
