package ghidra.app.util.bin.format.stabs;

import ghidra.app.util.bin.format.stabs.types.StabsCompositeTypeDescriptor;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

/**
 * Composite Type (Structure, Union, Enum) implementation of the StabSymbolDescriptor
 */
public class StabsCompositeSymbolDescriptor extends AbstractStabsSymbolDescriptor {

	private final DataType dt;
	private final StabsCompositeTypeDescriptor type;

	/**
	 * Constructs a new StabsCompositeSymbolDescriptor
	 * @param stab the portion of the stab containing this descriptor
	 * @param file the file containing this descriptor
	 * @throws StabsParseException if the descriptor or one it relies on is invalid
	 */
	StabsCompositeSymbolDescriptor(String stab, StabsFile file) throws StabsParseException {
		super(stab, file);
		this.dt = initDataType();
		this.type = StabsCompositeTypeDescriptor.getNamedDescriptor(this, getTypeSubStab());
	}

	@Override
	public StabsTypeDescriptor getTypeInformation() {
		return type;
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsSymbolDescriptorType getSymbolDescriptorType() {
		return StabsSymbolDescriptorType.COMPOSITE;
	}	

	private DataType initDataType() throws StabsParseException {
		String typeString = getTypeSubStab();
		DataType initDt = doGetDataType(typeString);
		if (initDt != null) {
			return dtm.resolve(initDt, REPLACE_HANDLER);
		}
		throw new StabsParseException(name, stab);
	}

	private DataType doGetDataType(String typeString) throws StabsParseException {
		switch (typeString.charAt(0)) {
			case 'e':
				return StabsCompositeTypeDescriptor.parseEnum(typeString, name, path, dtm);
			case 's':
				return new StructureDataType(path, name, 0, dtm);
			case 'u':
				return new UnionDataType(path, name, dtm);
			default:
				throw getError();
		}
	}

}
