package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Model for the __pbase_type_info class.
 */
public class PBaseTypeInfoModel extends AbstractPBaseTypeInfoModel {

	public static final String STRUCTURE_NAME = "__pbase_type_info";
	public static final String DESCRIPTION = "Model for Pointer Base Type Info";

	public static final String ID_STRING = "N10__cxxabiv117__pbase_type_infoE";

	private DataType typeInfoDataType;

	/**
	 * Constructs a new PBaseTypeInfoModel.
	 * 
	 * @param program the program containing the __pbase_type_info.
	 * @param address the address of the __pbase_type_info.
	 */
	public PBaseTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	@Override
	public String getIdentifier() {
		return ID_STRING;
	}

	/**
	 * Gets the __pbase_type_info datatype.
	 * 
	 * @return the __pbase_type_info datatype.
	 */
	@Override
	public DataType getDataType() {
		if (typeInfoDataType == null) {
			typeInfoDataType = getDataType(program.getDataTypeManager());
		}
		return typeInfoDataType;
	}

	/**
	 * Gets the __pbase_type_info datatype.
	 * 
	 * @param dtm
	 * @return the __pbase_type_info datatype.
	 */
	public static DataType getDataType(DataTypeManager dtm) {
		return getPBase(dtm);
	}
}
