package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class PBaseTypeInfoModel extends AbstractPBaseTypeInfoModel {

    public static final String STRUCTURE_NAME = "__pbase_type_info";
    public static final String DESCRIPTION = "Model for Pointer Base Type Info";

    public static final String ID_STRING = "N10__cxxabiv117__pbase_type_infoE";

    private DataType typeInfoDataType;

	/**
	 * Gets a new PBaseTypeInfoModel
	 * @param program the program containing the {@value #STRUCTURE_NAME}
	 * @param address the address of the {@value #STRUCTURE_NAME}
	 * @return the new PBaseTypeInfoModel
	 * @throws InvalidDataTypeException if the data at the address
	 * is not a valid {@value #STRUCTURE_NAME}
	 */
	public static PBaseTypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new PBaseTypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(getErrorMessage(address));
	}

    private PBaseTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    /**
     * Gets the __pbase_type_info datatype.
     */
    @Override
    public DataType getDataType() {
        if (typeInfoDataType == null) {
            typeInfoDataType = getDataType(program.getDataTypeManager());
        }
        return typeInfoDataType;
    }

    /**
     * Gets the {@value #STRUCTURE_NAME} datatype
     * @param dtm the DataTypeManager
     * @return the {@value #STRUCTURE_NAME} datatype
     */
    public static DataType getDataType(DataTypeManager dtm) {
        return getPBase(dtm);
    }
}
