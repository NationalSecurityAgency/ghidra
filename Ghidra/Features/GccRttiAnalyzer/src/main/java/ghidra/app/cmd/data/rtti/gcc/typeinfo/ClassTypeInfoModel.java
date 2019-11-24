package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.DataType;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;

/**
 * Model for the __class_type_info class.
 */
public class ClassTypeInfoModel extends AbstractClassTypeInfoModel {

	static final String STRUCTURE_NAME = "__class_type_info";
	private static final String DESCRIPTION = "Model for Class Type Info";

	public static final String ID_STRING = "N10__cxxabiv117__class_type_infoE";

	/**
	 * Constructs a new ClassTypeInfoModel.
	 * 
	 * @param program the program containing the __class_type_info.
	 * @param address the address of the __class_type_info.
	 */
	public ClassTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	/**
	 * Gets the __class_type_info datatype.
	 * 
	 * @return the __class_type_info datatype.
	 */
	@Override
	public DataType getDataType() {
		return getDataType(STRUCTURE_NAME, DESCRIPTION);
	}

	/**
	 * Gets the __class_type_info datatype.
	 * 
	 * @param dtm
	 * @return the __class_type_info datatype.
	 */
	public static DataType getDataType(DataTypeManager dtm) {
		return getDataType(dtm, STRUCTURE_NAME, DESCRIPTION);
	}

	/**
	 * Gets a pointer to a __class_type_info datatype.
	 * 
	 * @param dtm
	 * @return __class_type_info *
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
