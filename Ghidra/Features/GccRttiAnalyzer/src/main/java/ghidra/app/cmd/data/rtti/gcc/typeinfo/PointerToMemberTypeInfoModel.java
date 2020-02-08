package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

/**
 * Model for the {@value #STRUCTURE_NAME} class.
 */
public final class PointerToMemberTypeInfoModel extends AbstractPBaseTypeInfoModel {

    public static final String STRUCTURE_NAME = "__pointer_to_member_type_info";
    private static final String DESCRIPTION = "Model for Pointer To Member Type Info";
    public static final String ID_STRING = "N10__cxxabiv129__pointer_to_member_type_infoE";

    private static final int CONTEXT_ORDINAL = 1;
    private DataType typeInfoDataType;

	/**
	 * Gets a new PointerToMemberTypeInfoModel
	 * @param program the program containing the {@value #STRUCTURE_NAME}
	 * @param address the address of the {@value #STRUCTURE_NAME}
	 * @return the new PointerToMemberTypeInfoModel
	 * @throws InvalidDataTypeException if the data at the address
	 * is not a valid {@value #STRUCTURE_NAME}
	 */
	public static PointerToMemberTypeInfoModel getModel(Program program, Address address)
		throws InvalidDataTypeException {
			if (isValid(program, address, ID_STRING)) {
				return new PointerToMemberTypeInfoModel(program, address);
			}
			throw new InvalidDataTypeException(getErrorMessage(address));
	}

    private PointerToMemberTypeInfoModel(Program program, Address address) {
        super(program, address);
    }

    @Override
    public String getIdentifier() {
        return ID_STRING;
    }

    /**
     * Gets the __pointer_to_member_type_info datatype
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
        StructureDataType struct = new StructureDataType(superDt.getCategoryPath(), STRUCTURE_NAME, 0, dtm);
        struct.add(superDt, SUPER_NAME, null);
        struct.add(ClassTypeInfoModel.getPointer(dtm), "__context", null);
        struct.setDescription(DESCRIPTION);
        return alignDataType(struct, dtm);
    }

    /**
     * Gets the ClassTypeInfo containing the member being pointed to.
     * @return the ClassTypeInfo containing the member being pointed to.
     */
    public ClassTypeInfo getContext() {
        Structure struct = (Structure) getDataType();
        DataTypeComponent comp = struct.getComponent(CONTEXT_ORDINAL);
        Address pointee = getAbsoluteAddress(program, address.add(comp.getOffset()));
        return (ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, pointee);
    }

}
