package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;

/**
 * Model for the __si_class_type_info class.
 */
public class SiClassTypeInfoModel extends AbstractSiClassTypeInfoModel {

	static final String STRUCTURE_NAME = "__si_class_type_info";
	private static final String DESCRIPTION = "Model for Single Inheritance Class Type Info";
	public static final String ID_STRING = "N10__cxxabiv120__si_class_type_infoE";

	private static final String BASE_TYPE = "__base_type";
	private DataType typeInfoDataType;

	/**
	 * Constructs a new SiClassTypeInfoModel.
	 * 
	 * @param program the program containing the __si_class_type_info.
	 * @param address the address of the __si_class_type_info.
	 */
	public SiClassTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	@Override
	public String getIdentifier() {
		return ID_STRING;
	}

	/**
	 * Gets the __si_class_type_info datatype.
	 * 
	 * @return the __si_class_type_info datatype.
	 */
	@Override
	public DataType getDataType() {
		if (typeInfoDataType == null) {
			typeInfoDataType = getDataType(program.getDataTypeManager());
		}
		return typeInfoDataType;
	}

	/**
	 * Gets the __si_class_type_info datatype.
	 * 
	 * @param dtm
	 * @return the __si_class_type_info datatype.
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
		struct.add(PointerDataType.getPointer(superDt, dtm), BASE_TYPE, null);
		struct.setDescription(DESCRIPTION);
		return alignDataType(struct, dtm);
	}
}
