package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;

/**
 * Model for the type_info class.
 */
public class TypeInfoModel extends AbstractTypeInfoModel {

	public static final String STRUCTURE_NAME = "type_info";
	private static final String DESCRIPTION = "Model for the base Type Info";
	public static final String ID_STRING = "St9type_info";

	private static final String VPTR = "_vptr";
	private static final String NAME = "__name";
	protected static final int NAME_ORDINAL = 1;

	/**
	 * Constructs a new TypeInfoModel.
	 * 
	 * @param program the program containing the type_info.
	 * @param address the address of the type_info.
	 */
	public TypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	@Override
	public DataType getDataType() {
		return getDataType(program.getDataTypeManager());
	}

	/**
	 * Gets the type_info datatype.
	 * 
	 * @return the type_info datatype.
	 */
	public static DataType getDataType(DataTypeManager dtm) {
		DataType existingDt = dtm.getDataType(STD_PATH, STRUCTURE_NAME);
		if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
			return existingDt;
		}
		StructureDataType struct = new StructureDataType(STD_PATH, STRUCTURE_NAME, 0, dtm);
		struct.add(dtm.getPointer(VoidDataType.dataType), VPTR, null);
		struct.add(PointerDataType.getPointer(StringDataType.dataType, dtm), NAME, null);
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
