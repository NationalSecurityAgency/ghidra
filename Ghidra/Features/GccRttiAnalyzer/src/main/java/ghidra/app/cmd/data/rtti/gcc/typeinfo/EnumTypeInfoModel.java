package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;

import static ghidra.program.database.data.DataTypeUtilities.findDataType;

/**
 * Model for the __enum_type_info class.
 */
public final class EnumTypeInfoModel extends AbstractTypeInfoModel {

	public static final String STRUCTURE_NAME = "__enum_type_info";
	public static final String ID_STRING = "N10__cxxabiv116__enum_type_infoE";
	private static final String DESCRIPTION = "Model for Enum Type Info";

	private DataType typeInfoDataType;

	/**
	 * Constructs a new EnumTypeInfoModel.
	 * 
	 * @param program the program containing the __enum_type_info.
	 * @param address the address of the __enum_type_info.
	 */
	public EnumTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	@Override
	public String getIdentifier() {
		return ID_STRING;
	}

	/**
	 * Gets the __enum_type_info datatype.
	 * 
	 * @return __enum_type_info datatype.
	 */
	@Override
	public DataType getDataType() {
		if (typeInfoDataType == null) {
			typeInfoDataType = getDataType(STRUCTURE_NAME, DESCRIPTION);
		}
		return typeInfoDataType;
	}

	/**
	 * Gets the __enum_type_info datatype
	 * @param dtm
	 * @return __enum_type_info datatype.
	 */
	public static DataType getDataType(DataTypeManager dtm) {
		return getDataType(dtm, STRUCTURE_NAME, DESCRIPTION);
	}

	@Override
	public DataType getRepresentedDataType() throws InvalidDataTypeException {
		// __enum_type_info does not provide any information regarding the type.
		DataTypeManager dtm = program.getDataTypeManager();
		DataType result = findDataType(dtm, getNamespace(), getName(), null);
		if (result == null) {
			int defaultLength = IntegerDataType.dataType.clone(dtm).getLength();
			DataTypePath path = TypeInfoUtils.getDataTypePath(this);
			result =
				new EnumDataType(path.getCategoryPath(), path.getDataTypeName(), defaultLength);
		}
		return result;
	}
}
