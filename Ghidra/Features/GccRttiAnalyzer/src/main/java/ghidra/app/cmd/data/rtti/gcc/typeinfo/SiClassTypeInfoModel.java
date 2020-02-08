package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;

/**
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class SiClassTypeInfoModel extends AbstractSiClassTypeInfoModel {

    public static final String STRUCTURE_NAME = "__si_class_type_info";
    private static final String DESCRIPTION = "Model for Single Inheritance Class Type Info";

    public static final String ID_STRING = "N10__cxxabiv120__si_class_type_infoE";
    private DataType typeInfoDataType;

	/**
	 * Gets a new SiClassTypeInfoModel
	 * @param program the program containing the {@value #STRUCTURE_NAME}
	 * @param address the address of the {@value #STRUCTURE_NAME}
	 * @return the new SiClassTypeInfoModel
	 * @throws InvalidDataTypeException if the data at the address
	 * is not a valid {@value #STRUCTURE_NAME}
	 */
	public static SiClassTypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new SiClassTypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(getErrorMessage(address));
	}

    private SiClassTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    /**
     * Gets the __si_class_type_info datatype.
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
        DataType superDt = ClassTypeInfoModel.getDataType(dtm);
        DataType existingDt = dtm.getDataType(superDt.getCategoryPath(), STRUCTURE_NAME);
        if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
            return existingDt;
        }
        StructureDataType struct = new StructureDataType(
            superDt.getCategoryPath(), STRUCTURE_NAME, 0, dtm);
        struct.add(superDt, SUPER+ClassTypeInfoModel.STRUCTURE_NAME, null);
        struct.add(PointerDataType.getPointer(superDt, dtm), "__base_type", null);
        struct.setDescription(DESCRIPTION);
        return alignDataType(struct, dtm);
    }
}
