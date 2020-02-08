package ghidra.app.cmd.data.rtti.gcc.typeinfo;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.app.cmd.data.rtti.gcc.GccUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;

import static ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER;

/**
 * Model for the {@value #DATA_TYPE_NAME} in the {@value BaseClassTypeInfoModel#STRUCTURE_NAME}
 * helper class
 */
public final class VmiOffsetFlagsModel {

    private static final String DATA_TYPE_NAME = "__offset_flags";
    private static final String DESCRIPTION = "Model for the vmi offset flags";

    static final int VIRTUAL_MASK = 1;
    static final int PUBLIC_MASK = 2;

    private Program program;
    private Address address;

    VmiOffsetFlagsModel(Program program, Address address) {
        this.program = program;
        this.address = address;
    }

	/**
	 * Checks if the virtual bit is set
	 * @return true if the virtual bit is set
	 */
    public boolean isVirtual() {
        MemBuffer buf = new MemoryBufferImpl(program.getMemory(), address);
        return isVirtual(buf, program.getDataTypeManager());
    }

	/**
	 * Checks if the public bit is set
	 * @return true if the public bit is set
	 */
    public boolean isPublic() {
        MemBuffer buf = new MemoryBufferImpl(program.getMemory(), address);
        return isPublic(buf, program.getDataTypeManager());
    }

	/**
	 * Gets the base class offset
	 * @return the base class offset
	 */
    public long getOffset() {
        MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), address);
        DataTypeManager dtm = program.getDataTypeManager();
        Structure struct = (Structure) getDataType(dtm);
        DataTypeComponent comp;
        if (dtm.getDataOrganization().isBigEndian()) {
            comp = struct.getComponent(0);
        } else {
            comp = struct.getComponent(1);
        }
        try {
            return buf.getBigInteger(comp.getOffset(), comp.getLength(), true).longValue();
        } catch (MemoryAccessException e) {
            return 0;
        }
    }

    static boolean isVirtual(MemBuffer buf, DataTypeManager dtm) {
        Structure struct = (Structure) getDataType(dtm);
        DataTypeComponent flagsComponent;
        if (dtm.getDataOrganization().isBigEndian()) {
            flagsComponent = struct.getComponent(1);
        } else {
            flagsComponent = struct.getComponent(0);
        }
        Enum flags = (Enum) flagsComponent.getDataType();
        Scalar value = (Scalar) flags.getValue(buf, flagsComponent.getDefaultSettings(), flags.getLength());
        return value.testBit(0);
    }

    static boolean isPublic(MemBuffer buf, DataTypeManager dtm) {
        Structure struct = (Structure) getDataType(dtm);
        DataTypeComponent flagsComponent;
        if (dtm.getDataOrganization().isBigEndian()) {
            flagsComponent = struct.getComponent(1);
        } else {
            flagsComponent = struct.getComponent(0);
        }
        Enum flags = (Enum) flagsComponent.getDataType();
        Scalar value = (Scalar) flags.getValue(buf, flagsComponent.getDefaultSettings(), flags.getLength());
        return value.testBit(1);
    }

    static DataType getDataType(DataTypeManager dtm) {
        StructureDataType struct = new StructureDataType(VmiClassTypeInfoModel.SUB_PATH, DATA_TYPE_NAME, 0, dtm);
        if (dtm.getDataOrganization().isBigEndian()) {
            struct.add(getOffsetFlags(dtm), "__offset", null);
            struct.add(getFlags(dtm), "__flags", null);
        } else {
            struct.add(getFlags(dtm), "__flags", null);
            struct.add(getOffsetFlags(dtm), "__offset", null);
        }
        struct.setInternallyAligned(true);
        DataType base = GccUtils.isLLP64(dtm) ? LongLongDataType.dataType.clone(dtm)
            : LongDataType.dataType.clone(dtm);
        int alignment = dtm.getDataOrganization().getAlignment(base, struct.getLength());
        struct.setMinimumAlignment(alignment);
        struct.setDescription(DESCRIPTION);
        return dtm.resolve(struct, KEEP_HANDLER);
    }

    private static DataType getOffsetFlags(DataTypeManager dtm) {
        DataOrganization org = dtm.getDataOrganization();
        int size = GccUtils.isLLP64(dtm) ? (org.getLongLongSize())
            : (org.getLongSize());
        return AbstractIntegerDataType.getSignedDataType(size - 1, dtm);
    }
    
    private static DataType getFlags(DataTypeManager dtm) {
        EnumDataType flags =
            new EnumDataType(VmiClassTypeInfoModel.SUB_PATH, "offset_flags", 1, dtm);
        flags.add("__virtual_mask", VIRTUAL_MASK);
        flags.add("__public_mask", PUBLIC_MASK);
        // the offset shift parameter is meaningless here
        return dtm.resolve(flags, KEEP_HANDLER);
    }
}