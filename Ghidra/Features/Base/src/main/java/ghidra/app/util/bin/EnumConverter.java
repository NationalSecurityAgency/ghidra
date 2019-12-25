package ghidra.app.util.bin;

import ghidra.program.model.data.DataType;

public interface EnumConverter {

    long getValue();

    DataType toDataType();
}
