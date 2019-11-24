package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

/**
 * Model for the __pointer_to_member_type_info class.
 */
public final class PointerToMemberTypeInfoModel extends AbstractPBaseTypeInfoModel {

	private static final String STRUCTURE_NAME = "__pointer_to_member_type_info";
	private static final String DESCRIPTION = "Model for Pointer To Member Type Info";
	public static final String ID_STRING = "N10__cxxabiv129__pointer_to_member_type_infoE";

	private static final String CONTEXT = "__context";
	private static final int CONTEXT_ORDINAL = 1;
	private DataType typeInfoDataType;

	/**
	 * Constructs a new PointerToMemberTypeInfoModel.
	 * 
	 * @param program the program containing the __pointer_to_member_type_info.
	 * @param address the address of the __pointer_to_member_type_info.
	 */
	public PointerToMemberTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	@Override
	public String getIdentifier() {
		return ID_STRING;
	}

	/**
	 * Gets the __pointer_to_member_type_info datatype.
	 * 
	 * @return __pointer_to_member_type_info datatype.
	 */
	@Override
	public DataType getDataType() {
		if (typeInfoDataType == null) {
			typeInfoDataType = getDataType(program.getDataTypeManager());
		}
		return typeInfoDataType;
	}

	/**
	 * Gets the __pointer_to_member_type_info datatype.
	 * 
	 * @param dtm
	 * @return __pointer_to_member_type_info datatype.
	 */
	public static DataType getDataType(DataTypeManager dtm) {
		DataType superDt = getPBase(dtm);
		DataType existingDt = dtm.getDataType(superDt.getCategoryPath(), STRUCTURE_NAME);
		if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
			return existingDt;
		}
		StructureDataType struct = new StructureDataType(
			superDt.getCategoryPath(), STRUCTURE_NAME, 0, dtm);
		struct.add(superDt, SUPER_NAME, null);
		struct.add(ClassTypeInfoModel.getPointer(dtm), CONTEXT, null);
		struct.setDescription(DESCRIPTION);
		return alignDataType(struct, dtm);
	}

	/**
	 * Gets the ClassTypeInfo containing the member being pointed to.
	 * 
	 * @return the ClassTypeInfo containing the member being pointed to.
	 */
	public ClassTypeInfo getContext() {
		Structure struct = (Structure) getDataType();
		DataTypeComponent comp = struct.getComponent(CONTEXT_ORDINAL);
		Address pointee = getAbsoluteAddress(program, address.add(comp.getOffset()));
		return (ClassTypeInfo) TypeInfoFactory.getTypeInfo(program, pointee);
	}

}
