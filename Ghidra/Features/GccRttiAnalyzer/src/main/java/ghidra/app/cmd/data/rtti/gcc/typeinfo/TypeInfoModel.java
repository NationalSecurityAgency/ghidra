package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;

/**
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class TypeInfoModel extends AbstractTypeInfoModel {

    public static final String STRUCTURE_NAME = "type_info";
    private static final String DESCRIPTION = "Model for the base Type Info";

    protected static final int NAME_ORDINAL = 1;

    public static final String ID_STRING = "St9type_info";

	/**
	 * Gets a new TypeInfoModel
	 * @param program the program containing the {@value #STRUCTURE_NAME}
	 * @param address the address of the {@value #STRUCTURE_NAME}
	 * @return the new TypeInfoModel
	 * @throws InvalidDataTypeException if the data at the address
	 * is not a valid {@value #STRUCTURE_NAME}
	 */
	public static TypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new TypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(getErrorMessage(address));
	}

    private TypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    public DataType getDataType() {
        return getDataType(program.getDataTypeManager());
    }

    /**
     * Gets the {@value #STRUCTURE_NAME} datatype
     * @param dtm the DataTypeManager
     * @return the {@value #STRUCTURE_NAME} datatype
     */
    public static DataType getDataType(DataTypeManager dtm) {
        DataType existingDt = dtm.getDataType(STD_PATH, STRUCTURE_NAME);
        if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
            return existingDt;
        }
        StructureDataType struct = new StructureDataType(STD_PATH, STRUCTURE_NAME, 0, dtm);
        struct.add(dtm.getPointer(VoidDataType.dataType), "_vptr", null);
        struct.add(PointerDataType.getPointer(StringDataType.dataType, dtm), "__name", null);
        struct.setDescription(DESCRIPTION);
        return alignDataType(struct, dtm);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    @Override
    public DataType getRepresentedDataType() {
        return getDataType();
    }

}
