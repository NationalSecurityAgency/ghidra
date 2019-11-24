package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.program.model.listing.Program;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.GccUtils;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;

import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.app.cmd.data.rtti.gcc.GccUtils.getCxxAbiCategoryPath;

/**
 * Model for the __vmi_class_type_info class.
 */
public class VmiClassTypeInfoModel extends AbstractClassTypeInfoModel {

	private static final String STRUCTURE_NAME = "__vmi_class_type_info";
	private static final String DESCRIPTION =
		"Model for Virtual Multiple Inheritance Class Type Info";

	public static final String ID_STRING = "N10__cxxabiv121__vmi_class_type_infoE";

	private static final String FLAGS_NAME = "__flags";
	private static final String BASE_COUNT_NAME = "__base_count";
	private static final String ARRAY_NAME = "__base_info";

	private static final String FLAGS = "__flags_masks";
	private static final String NON_PUBLIC_BASE = "non_public_base_mask";
	private static final String PUBLIC_BASE = "public_base_mask";
	private static final String DIAMOND_MASK_NAME = "__diamond_shaped_mask";
	private static final String NON_DIAMOND_MASK_NAME = "__non_diamond_repeat_mask";
	private static final String FLAGS_UNKNOWN = "__flags_unknown_mask";

	private static final int FLAGS_ORDINAL = 1;
	private static final int BASE_COUNT_ORDINAL = 2;
	private static final int BASE_ARRAY_ORDINAL = 3;

	protected static final CategoryPath SUB_PATH =
		new CategoryPath(getCxxAbiCategoryPath(), STRUCTURE_NAME);

	public enum Flags {
		NON_DIAMOND,
		DIAMOND,
		NON_PUBLIC,
		PUBLIC,
		UNKNOWN
	}

	private BaseClassTypeInfoModel[] bases;
	private Flags flags;

	/**
	 * Constructs a new VmiClassTypeInfoModel.
	 * 
	 * @param program the program containing the __vmi_class_type_info.
	 * @param address the address of the __vmi_class_type_info.
	 */
	public VmiClassTypeInfoModel(Program program, Address address) {
		super(program, address);
		if (!typeName.equals(DEFAULT_TYPENAME)) {
			this.bases = getBases();
			this.flags = getFlags(getBuffer());
		}
	}

	/**
	 * Gets the __vmi_class_type_info datatype.
	 * 
	 * @return the __vmi_class_type_info datatype.
	 */
	@Override
	public Structure getDataType() {
		return getDataType(program.getDataTypeManager());
	}

	public Flags getFlags() {
		return flags;
	}

	/**
	 * Gets the __vmi_class_type_info datatype.
	 * 
	 * @param dtm
	 * @return the __vmi_class_type_info datatype.
	 */
	public static Structure getDataType(DataTypeManager dtm) {
		DataType existingDt = dtm.getDataType(GccUtils.getCxxAbiCategoryPath(), STRUCTURE_NAME);
		if (existingDt != null && existingDt.getDescription().equals(DESCRIPTION)) {
			return (Structure) existingDt;
		}
		StructureDataType struct =
			new StructureDataType(GccUtils.getCxxAbiCategoryPath(), STRUCTURE_NAME, 0, dtm);
		struct.add(ClassTypeInfoModel.getDataType(dtm),
				   AbstractTypeInfoModel.SUPER + ClassTypeInfoModel.STRUCTURE_NAME,
				   null);
		struct.add(getFlags(dtm, VmiClassTypeInfoModel.SUB_PATH), FLAGS_NAME, null);
		struct.add(IntegerDataType.dataType.clone(dtm), BASE_COUNT_NAME, null);
		struct.setFlexibleArrayComponent(
			BaseClassTypeInfoModel.getDataType(dtm), ARRAY_NAME, null);
		struct.setDescription(DESCRIPTION);
		Structure result = (Structure) dtm.resolve(struct, KEEP_HANDLER);
		if (!result.isNotYetDefined()) {
			Structure flexComponent =
				(Structure) result.getFlexibleArrayComponent().getDataType();
			DataTypeComponent baseFlagsComp = flexComponent.getComponent(
				BaseClassTypeInfoModel.FLAGS_ORDINAL);
			if (baseFlagsComp.getDataType() instanceof Structure) {
				return result;
			}
		}
		return (Structure) dtm.resolve(struct, REPLACE_HANDLER);
	}

	@Override
	public String getIdentifier() {
		return ID_STRING;
	}

	private Address getArrayAddress() {
		DataTypeComponent arrayComponent = getDataType().getFlexibleArrayComponent();
		return address.add(arrayComponent.getOffset());
	}

	@Override
	public boolean hasParent() {
		return true;
	}

	private List<AbstractClassTypeInfoModel> getParents() throws InvalidDataTypeException {
		List<AbstractClassTypeInfoModel> parents = new ArrayList<>();
		if (bases == null) {
			// this SHOULD be impossible
			bases = getBases();
		}
		for (BaseClassTypeInfoModel base : bases) {
			if (!base.isVirtual()) {
				parents.add(base.getClassModel());
			}
		}
		try {
			parents.addAll(getInheritableVirtualParents());
		} catch (NullPointerException e) {
			throw e;
		}
		return parents;
	}

	@Override
	public ClassTypeInfo[] getParentModels() throws InvalidDataTypeException {
		validate();
		List<AbstractClassTypeInfoModel> parents = getParents();
		return parents.toArray(new ClassTypeInfo[parents.size()]);
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() throws InvalidDataTypeException {
		Set<ClassTypeInfo> result = new LinkedHashSet<>();
		for (BaseClassTypeInfoModel base : bases) {
			ClassTypeInfo parent = base.getClassModel();
			result.addAll(parent.getVirtualParents());
			if (base.isVirtual()) {
				result.add(parent);
			}
		}
		return result;
	}

	private Set<AbstractClassTypeInfoModel> getInheritableVirtualParents()
		throws InvalidDataTypeException {
			Set<AbstractClassTypeInfoModel> result = new LinkedHashSet<>();
			for (BaseClassTypeInfoModel base : bases) {
				AbstractClassTypeInfoModel parent = base.getClassModel();
				if (base.isVirtual()) {
					result.add(parent);
				}
				parent.getVirtualParents().forEach(
					(a) -> result.add((AbstractClassTypeInfoModel) a));
			}
			return result;
	}

	private int getBaseCount() {
		MemBuffer buf = getBuffer();
		DataTypeComponent comp = getDataType().getComponent(BASE_COUNT_ORDINAL);
		try {
			return buf.getVarLengthInt(comp.getOffset(), comp.getLength());
		} catch (MemoryAccessException e) {
			Msg.error(this, e);
			return 0;
		}
	}

	/**
	 * Gets this __vmi_class_type_info's __base_class_type_info array.
	 * 
	 * @return the BaseClassTypeInfo[] representation of the __base_class_type_info array.
	 */
	public BaseClassTypeInfoModel[] getBases() {
		if (bases != null) {
			return bases;
		}
		BaseClassTypeInfoModel base = new BaseClassTypeInfoModel(program, getArrayAddress());
		int baseCount = getBaseCount();
		bases = new BaseClassTypeInfoModel[baseCount];
		for (int i = 0; i < baseCount; i++) {
			bases[i] = new BaseClassTypeInfoModel(program, base.getAddress());
			base.advance();
		}
		return bases;
	}

	/**
	 * Gets a list of the offsets of each derived class within this class.
	 * 
	 * @return a list containing the offsets of each derived class within this class.
	 */
	public List<Long> getOffsets() {
		List<Long> result = new ArrayList<>();
		for (BaseClassTypeInfoModel base : bases) {
			if(!base.isVirtual()) {
				result.add((long) base.getOffset());
			}
		}
		try {
			long[] offsets = ((VtableModel) getVtable()).getBaseOffsetArray();
			Arrays.sort(offsets);
			for (int i = 1; i < offsets.length; i++) {
				result.add(offsets[i]);
			}
		} catch (InvalidDataTypeException e) {}
		return result;
	}

	private static DataType getFlags(DataTypeManager dtm, CategoryPath path) {
		DataType integer = IntegerDataType.dataType.clone(dtm);
		EnumDataType flags =
			new EnumDataType(path, FLAGS, integer.getLength(), dtm);

		// Populate the flags mask
		flags.add(NON_DIAMOND_MASK_NAME, 1);
		flags.add(DIAMOND_MASK_NAME, 2);
		flags.add(NON_PUBLIC_BASE, 4);
		flags.add(PUBLIC_BASE, 8);
		flags.add(FLAGS_UNKNOWN, 16);
		return dtm.resolve(flags, KEEP_HANDLER);
	}

	/**
	 * Gets the value of this datatypes's __flags_mask
	 * 
	 * @param buf
	 * @return the value of this datatypes's __flags_mask
	 */
	public Flags getFlags(MemBuffer buf) {
		try {
			DataTypeComponent comp = getDataType().getComponent(FLAGS_ORDINAL);
			int offset = comp.getOffset();
			int length = comp.getLength();
			switch(buf.getVarLengthInt(offset, length)) {
				case 1:
					return Flags.NON_DIAMOND;
				case 2:
					return Flags.DIAMOND;
				case 4:
					return Flags.NON_PUBLIC;
				case 8:
					return Flags.PUBLIC;
				case 16:
				default:
					return Flags.UNKNOWN;
			}
		} catch (MemoryAccessException e) {
			return Flags.UNKNOWN;
		}
	}

	/**
	 * Gets the DataType representation of the __base_class_type_info array.
	 * 
	 * @return the DataType representation of the __base_class_type_info array.
	 */
	public DataType getBaseArrayDataType() {
		int baseCount = getBaseCount();
		DataType base = BaseClassTypeInfoModel.getDataType(program.getDataTypeManager());
		return new ArrayDataType(base, baseCount, base.getLength(), program.getDataTypeManager());
	}

	/**
	 * Gets the address of the __base_class_type_info array.
	 * 
	 * @return the address of the __base_class_type_info array.
	 */
	public Address getBaseArrayAddress() {
		return address.add(getDataType().getComponent(BASE_ARRAY_ORDINAL).getOffset());
	}
}
