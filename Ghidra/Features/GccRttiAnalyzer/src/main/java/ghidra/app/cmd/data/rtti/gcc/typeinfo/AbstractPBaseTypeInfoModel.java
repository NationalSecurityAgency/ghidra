package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.scalar.Scalar;

import static ghidra.app.cmd.data.rtti.gcc.GccUtils.getCxxAbiCategoryPath;
import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;
import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory;

/**
 * Base Model for __pbase_type_info and its derivatives.
 */
public abstract class AbstractPBaseTypeInfoModel extends AbstractTypeInfoModel {

	private static final CategoryPath FLAGS_PATH = new CategoryPath(
		getCxxAbiCategoryPath(), PBaseTypeInfoModel.STRUCTURE_NAME);

	protected static final String SUPER_NAME = SUPER + PBaseTypeInfoModel.STRUCTURE_NAME;

	private static final String FLAGS = "__flags";
	private static final String POINTEE = "__pointee";
	private static final String QUALIFIER_MASKS = "__qualifier_masks";
	private static final String CONST = "__const_mask";
	private static final String VOLATILE = "__volatile_mask";
	private static final String RESTRICT = "__restrict_mask";
	private static final String INCOMPLETE = "__incomplete_mask";
	private static final String INCOMPLETE_CLASS = "__incomplete_class_mask";
	private static final String TRANSACTION_SAFE = "__transaction_safe_mask";
	private static final String NOEXCEPT = "__noexcept_mask";
	private static final int POINTEE_ORDINAL = 2;

	private DataType dataType = null;

	private enum Mask {
		CONSTANT,
		VOLATILE,
		RESTRICT,
		INCOMPLETE,
		INCOMPLETE_CLASS,
		TRANACTION_SAFE,
		NO_EXCEPT
	}

	/**
	 * Constructs a new AbstractPBaseTypeInfoModel.
	 * 
	 * @param program the program containing the AbstractPBaseTypeInfoModel.
	 * @param address the address of the AbstractPBaseTypeInfoModel.
	 */
	public AbstractPBaseTypeInfoModel(Program program, Address address) {
		super(program, address);
	}

	/**
	 * Gets the DataType for the __qualifier_masks
	 * 
	 * @param dtm
	 * @return the __qualifier_masks DataType
	 */
	public static DataType getFlags(DataTypeManager dtm) {
		EnumDataType flags = new EnumDataType(
			FLAGS_PATH, QUALIFIER_MASKS, dtm.getDataOrganization().getIntegerSize());

		// According to cxxabi.h
		flags.add(CONST, 1);
		flags.add(VOLATILE, 2);
		flags.add(RESTRICT, 4);
		flags.add(INCOMPLETE, 8);
		flags.add(INCOMPLETE_CLASS, 16);
		flags.add(TRANSACTION_SAFE, 0x20);
		flags.add(NOEXCEPT, 0x40);
		DataType result = dtm.resolve(flags, KEEP_HANDLER);
		return result.getLength() <= 1 ? dtm.resolve(flags, REPLACE_HANDLER) : result;
	}

	protected static DataType getPBase(DataTypeManager dtm) {
		DataType existingDt = dtm.getDataType(
			getCxxAbiCategoryPath(), PBaseTypeInfoModel.STRUCTURE_NAME);
		if (existingDt != null &&
			existingDt.getDescription().equals(PBaseTypeInfoModel.DESCRIPTION)) {
				return existingDt;
		}
		DataType superDt = TypeInfoModel.getDataType(dtm);
		StructureDataType struct = new StructureDataType(
			getCxxAbiCategoryPath(), PBaseTypeInfoModel.STRUCTURE_NAME, 0, dtm);
		struct.add(superDt, SUPER+TypeInfoModel.STRUCTURE_NAME, null);
		struct.add(getFlags(dtm), FLAGS, null);
		struct.add(
			PointerDataType.getPointer(TypeInfoModel.getDataType(dtm), dtm), POINTEE, null);
		struct.setDescription(PBaseTypeInfoModel.DESCRIPTION);
		struct.setInternallyAligned(true);
		struct.adjustInternalAlignment();
		DataType result = dtm.resolve(struct, KEEP_HANDLER);
		return result.getLength() <= 1 ? dtm.resolve(struct, REPLACE_HANDLER) : result;
	}

	private Scalar getFlagsValue() {
		DataTypeComponent comp = ((Structure) getDataType()).getComponent(1);
		Enum flags = (Enum) comp.getDataType();
		DumbMemBufferImpl dumBuf = new DumbMemBufferImpl(
			program.getMemory(), address.add(comp.getOffset()));
		return (Scalar) flags.getValue(dumBuf, flags.getDefaultSettings(), flags.getLength());
	}

	private boolean testFlags(Mask mask) {
		switch(mask) {
			case CONSTANT:
				return getFlagsValue().testBit(0);
			case VOLATILE:
				return getFlagsValue().testBit(1);
			case RESTRICT:
				return getFlagsValue().testBit(2);
			case INCOMPLETE:
				return getFlagsValue().testBit(3);
			case INCOMPLETE_CLASS:
				return getFlagsValue().testBit(4);
			case TRANACTION_SAFE:
				return getFlagsValue().testBit(5);
			case NO_EXCEPT:
				return getFlagsValue().testBit(6);
			default:
				return false;
		}
	}

	/**
	 * Returns true if the pointed to datatype is const.
	 * 
	 * @return true if the pointed to datatype is const.
	 */
	public boolean isConst() {
		return testFlags(Mask.CONSTANT);
	}

	/**
	 * Returns true if the pointed to datatype is volatile.
	 * 
	 * @return true if the pointed to datatype is volatile.
	 */
	public boolean isVolatile() {
		return testFlags(Mask.VOLATILE);
	}

	/**
	 * Returns true if the pointed to datatype is restrict.
	 * 
	 * @return true if the pointed to datatype is restrict.
	 */
	public boolean isRestrict() {
		return testFlags(Mask.RESTRICT);
	}

	/**
	 * Returns true if the pointed to datatype is incomplete.
	 * 
	 * @return true if the pointed to datatype is incomplete.
	 */
	public boolean isIncomplete() {
		return testFlags(Mask.INCOMPLETE);
	}

	/**
	 * Returns true if the pointed to datatype is an incomplete class.
	 * 
	 * @return true if the pointed to datatype is an incomplete class.
	 */
	public boolean isIncompleteClass() {
		return testFlags(Mask.INCOMPLETE_CLASS);
	}

	/**
	 * Returns true if the pointed to datatype is transaction_safe (synchronized)
	 * 
	 * @return true if the pointed to datatype is transaction_safe (synchronized)
	 */
	public boolean isTransactionSafe() {
		return testFlags(Mask.TRANACTION_SAFE);
	}

	/**
	 * Returns true if the pointed to datatype is specified as noexcept.
	 * 
	 * @return true if the pointed to datatype is specified as noexcept.
	 */
	public boolean isNoExcept() {
		return testFlags(Mask.NO_EXCEPT);
	}

	/**
	 * Gets the TypeInfo base being pointed to.
	 * 
	 * @return the TypeInfo being pointed to.
	 * @throws InvalidDataTypeException
	 */
	public TypeInfo getPointee() throws InvalidDataTypeException {
		validate();
		Structure struct = (Structure) getDataType();
		DataTypeComponent comp;
		if (this instanceof PBaseTypeInfoModel) {
			comp = struct.getComponent(POINTEE_ORDINAL);
		} else {
			Structure baseDt = (Structure) struct.getComponent(0).getDataType();
			comp = baseDt.getComponent(POINTEE_ORDINAL);
		}
		Address pointee = getAbsoluteAddress(program, address.add(comp.getOffset()));
		return TypeInfoFactory.getTypeInfo(program, pointee);
	}

	@Override
	public DataType getRepresentedDataType() throws InvalidDataTypeException {
		validate();
		if (dataType == null) {
			DataType pointeeType = parseDataType(getPointee().getTypeName());
			dataType = program.getDataTypeManager().getPointer(pointeeType);
		}
		return dataType;
	}
}
