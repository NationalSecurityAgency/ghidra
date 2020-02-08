package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import static ghidra.app.cmd.data.rtti.gcc.GccUtils.getCxxAbiCategoryPath;

/**
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class PointerTypeInfoModel extends AbstractPBaseTypeInfoModel {

    public static final String STRUCTURE_NAME = "__pointer_type_info";
    public static final String ID_STRING = "N10__cxxabiv119__pointer_type_infoE";
    private static final String DESCRIPTION = "Model for Pointer Type Info";
    private DataType typeInfoDataType;

	/**
	 * Gets a new PointerTypeInfoModel
	 * @param program the program containing the {@value #STRUCTURE_NAME}
	 * @param address the address of the {@value #STRUCTURE_NAME}
	 * @return the new PointerTypeInfoModel
	 * @throws InvalidDataTypeException if the data at the address
	 * is not a valid {@value #STRUCTURE_NAME}
	 */
	public static PointerTypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new PointerTypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(getErrorMessage(address));
	}

    private PointerTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    /**
     * Gets the __pointer_type_info datatype.
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
        DataType superDt = getPBase(dtm);
        DataType existingDt = dtm.getDataType(superDt.getCategoryPath(), STRUCTURE_NAME);
        if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
            return existingDt;
        }
        StructureDataType struct = new StructureDataType(
            getCxxAbiCategoryPath(), STRUCTURE_NAME, 0, dtm);
        struct.add(superDt, SUPER_NAME, null);
        struct.setDescription(DESCRIPTION);
        return alignDataType(struct, dtm);
    }

}
