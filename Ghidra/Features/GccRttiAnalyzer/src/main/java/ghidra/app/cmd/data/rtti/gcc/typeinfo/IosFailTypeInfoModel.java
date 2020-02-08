package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

/**
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class IosFailTypeInfoModel extends AbstractSiClassTypeInfoModel {

    private static final String DESCRIPTION = "Model for IosFail Type Info";
    public static final String STRUCTURE_NAME = "__iosfail_type_info";

    public static final String ID_STRING = "St19__iosfail_type_info";

    private DataType typeInfoDataType;

	/**
	 * Gets a new IosFailTypeInfoModel
	 * @param program the program containing the {@value #STRUCTURE_NAME}
	 * @param address the address of the {@value #STRUCTURE_NAME}
	 * @return the new IosFailTypeInfoModel
	 * @throws InvalidDataTypeException if the data at the address
	 * is not a valid {@value #STRUCTURE_NAME}
	 */
	public static IosFailTypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new IosFailTypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(getErrorMessage(address));
	}

    private IosFailTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    /**
     * Gets the __iosfail_type_info datatype.
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
        DataType existingDt = dtm.getDataType(STD_PATH, STRUCTURE_NAME);
        if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
            return existingDt;
        }
        StructureDataType struct = new StructureDataType(STD_PATH, STRUCTURE_NAME, 0, dtm);
        struct.add(SiClassTypeInfoModel.getDataType(dtm), SUPER+SiClassTypeInfoModel.STRUCTURE_NAME, null);
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
