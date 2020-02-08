package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.DataType;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;

/**
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class ClassTypeInfoModel extends AbstractClassTypeInfoModel {

    public static final String STRUCTURE_NAME = "__class_type_info";
    private static final String DESCRIPTION = "Model for Class Type Info";

    public static final String ID_STRING = "N10__cxxabiv117__class_type_infoE";

	/**
	 * Gets a new ClassTypeInfoModel
	 * @param program the program containing the {@value #STRUCTURE_NAME}
	 * @param address the address of the {@value #STRUCTURE_NAME}
	 * @return the new ClassTypeInfoModel
	 * @throws InvalidDataTypeException if the data at the address
	 * is not a valid {@value #STRUCTURE_NAME}
	 */
	public static ClassTypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new ClassTypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(getErrorMessage(address));
	}

    private ClassTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    /**
     * Gets the __class_type_info datatype.
     */
    @Override
    public DataType getDataType() {
        return getDataType(STRUCTURE_NAME, DESCRIPTION);
    }

    /**
     * Gets the {@value #STRUCTURE_NAME} datatype
     * @param dtm the DataTypeManager
     * @return the {@value #STRUCTURE_NAME} datatype
     */
    public static DataType getDataType(DataTypeManager dtm) {
        return getDataType(dtm, STRUCTURE_NAME, DESCRIPTION);
    }

    /**
     * Gets a pointer to a __class_type_info datatype
     * @param dtm the datatype manager
     * @return {@value #STRUCTURE_NAME}*
     */
    public static Pointer getPointer(DataTypeManager dtm) {
        return PointerDataType.getPointer(getDataType(dtm), dtm);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    @Override
    public boolean hasParent() {
        return false;
    }

    @Override
    public ClassTypeInfo[] getParentModels() {
        return new ClassTypeInfo[0];
    }

}
