package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;


/**
 * Model for the __fundamental_type_info class.
 */
public final class FundamentalTypeInfoModel extends AbstractTypeInfoModel {

	public static final String STRUCTURE_NAME = "__fundamental_type_info";
	public static final String ID_STRING = "N10__cxxabiv123__fundamental_type_infoE";
	private static final String DESCRIPTION = "Model for Fundamental Type Info";

	private DataType typeInfoDataType;

	/**
	 * Constructs a new FundamentalTypeInfoModel.
	 * 
	 * @param program the program containing the __fundamental_type_info.
	 * @param address the address of the __fundamental_type_info.
	 */
	public FundamentalTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	@Override
	public String getIdentifier() {
		return ID_STRING;
	}

	/**
	 * Gets the __fundamental_type_info datatype.
	 * 
	 * @return the __fundamental_type_info datatype.
	 */
	@Override
	public DataType getDataType() {
		if (typeInfoDataType == null) {
			typeInfoDataType = getDataType(STRUCTURE_NAME, DESCRIPTION);
		}
		return typeInfoDataType;
	}

	/**
	 * Gets the __fundamental_type_info datatype.
	 * 
	 * @param dtm
	 * @return the __fundamental_type_info datatype.
	 */
	public static DataType getDataType(DataTypeManager dtm) {
		return getDataType(dtm, STRUCTURE_NAME, DESCRIPTION);
	}

}
