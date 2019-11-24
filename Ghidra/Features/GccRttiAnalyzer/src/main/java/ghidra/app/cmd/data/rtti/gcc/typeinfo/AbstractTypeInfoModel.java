package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;
import ghidra.app.util.demangler.DemangledDataType;
import ghidra.app.util.demangler.DemangledFunctionReference;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.data.*;

import static ghidra.app.util.demangler.DemanglerUtil.demangle;
import static ghidra.app.cmd.data.rtti.gcc.GccUtils.getCxxAbiCategoryPath;
import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

/**
 * Base Model for Type Info and its derivatives.
 */
public abstract class AbstractTypeInfoModel implements TypeInfo {

	protected static final String DEFAULT_TYPENAME = "";

	protected static final int BASE_ORDINAL = 0;

	protected Program program;
	protected Address address;
	private DataType dataType = null;

	protected String typeName = DEFAULT_TYPENAME;
	protected Namespace namespace;
	private MemoryBufferImpl buf;

	protected static final String SUPER = "super_";
	protected static final CategoryPath STD_PATH = new CategoryPath(CategoryPath.ROOT, "std");

	private static final String SUPER_TYPE_INFO = SUPER+TypeInfoModel.STRUCTURE_NAME;
	private static final Pattern TYPE_PATTERN = Pattern.compile(".*_\\((.*)\\)");
	private static final Pattern FUNCTION_PATTERN = Pattern.compile("(.*)\\S*?\\((.*)\\)");

	/**
	 * Constructs a new AbstractTypeInfoModel.
	 * 
	 * @param program the program containing the AbstractTypeInfoModel.
	 * @param address the address of the AbstractTypeInfoModel.
	 */
	protected AbstractTypeInfoModel(Program program, Address address) {
		this.program = program;
		this.address = address;
		this.buf = new MemoryBufferImpl(program.getMemory(), address);
		this.typeName = TypeInfoUtils.getTypeName(program, address);
		this.namespace = TypeInfoUtils.getNamespaceFromTypeName(program, typeName);
	}

	@Override
	public void validate() throws InvalidDataTypeException {
		if (!TypeInfoUtils.getIDString(program, address).equals(getIdentifier())) {
			throw new InvalidDataTypeException(
				"Invalid "+getIdentifier()+" instance at "+address.toString());
		}
		if (typeName.equals(DEFAULT_TYPENAME)) {
			throw new InvalidDataTypeException(
				getIdentifier()+" at "+address.toString()+" is a relocation");
		}
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public final boolean equals(Object object) {
		if (!(object instanceof TypeInfo)) {
			return false;
		}
		return ((TypeInfo) object).getAddress().equals(address);
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public final int hashCode() {
		return typeName.hashCode();
	}

	@Override
	public Namespace getNamespace() throws InvalidDataTypeException {
		return namespace;
	}

	protected MemBuffer getBuffer() {
		return buf;
	}

	protected static DataType alignDataType(StructureDataType struct, DataTypeManager dtm) {
		struct.setInternallyAligned(true);
		struct.adjustInternalAlignment();
		DataType result = dtm.resolve(struct, KEEP_HANDLER);
		return result.getLength() <= 1 ? dtm.resolve(struct, REPLACE_HANDLER) : result;
	}

	@Override
	public final String getName() throws InvalidDataTypeException {
		return namespace.getName();
	}

	protected Structure getDataType(String dtName, String description) {
		return getDataType(program.getDataTypeManager(), dtName, description);
	}

	protected static Structure getDataType(DataTypeManager dtm, String name, String description) {
		DataType existingDt = dtm.getDataType(getCxxAbiCategoryPath(), name);
		if (existingDt != null && existingDt.getDescription().equals(description)) {
			return (Structure) existingDt;
		}
		StructureDataType struct = new StructureDataType(getCxxAbiCategoryPath(), name, 0, dtm);
		struct.add(TypeInfoModel.getDataType(dtm), SUPER_TYPE_INFO, null);
		struct.setDescription(description);
		return (Structure) alignDataType(struct, dtm);
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public String getTypeName() throws InvalidDataTypeException {
		validate();
		return typeName;
	}

	@Override
	public DataType getRepresentedDataType() throws InvalidDataTypeException {
		validate();
		if (dataType == null) {
			dataType = parseDataType(typeName);
		}
		return dataType;
	}

	private static DemangledDataType getDemangledType(String demangled) {
		if (demangled.contains(DemangledDataType.UNSIGNED)) {
			demangled = demangled.replace(DemangledDataType.UNSIGNED+" ", "u");
		}
		if (demangled.contains(" ")) {
			int index = demangled.indexOf(" ");
			demangled = demangled.substring(0, index);
		}
		return new DemangledDataType(demangled);
	}

	protected DemangledFunctionReference getDemangledFunction(String signature) {
		DemangledFunctionReference method = new DemangledFunctionReference();
		Matcher matcher = FUNCTION_PATTERN.matcher(signature);
		if (matcher.matches()) {
			method.setReturnType(getDemangledType(matcher.group(1)));
			String[] parameters = matcher.group(2).split(",");
			for (String parameter : parameters) {
				if (parameter.equals("")) {
					parameter = DemangledDataType.VOID;
				}
				method.addParameter(getDemangledType(parameter));
			}
		}
		return method;
	}

	protected DataType parseDataType(String dataTypeName) {
		DemangledObject demangled = demangle("_Z1_"+dataTypeName);
		if (demangled != null) {
			Matcher matcher = TYPE_PATTERN.matcher(demangled.getSignature(false));
			if (matcher.matches()) {
				DataTypeManager dtm = program.getDataTypeManager();
				if (matcher.group(1).contains("(")) {
					// we have a demangled function
					DemangledFunctionReference method = getDemangledFunction(matcher.group(1));
					return ((Pointer) method.getDataType(dtm)).getDataType();
				}
				DemangledDataType dt = new DemangledDataType(matcher.group(1));
				return dt.getDataType(dtm);
			}
		} return null;
	}
}