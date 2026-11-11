package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.AbstractStabsTest;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.TypedefDataType;

import org.junit.Test;

public class StabArrayTypeDescriptorTest extends AbstractStabsTest {

	private static final String TYPE_NAME = "array_test";

	private static final String[] STABS = new String[]{
		"main.c",
		"int:t(0,1)=r(0,1);-2147483648;2147483647;",
		TYPE_NAME+":t(1,1)=ar(0,1);0;15;(0,1)"
	};

	public StabArrayTypeDescriptorTest() {
		super(STABS);
	}

	@Test
	public void parseTest() throws Exception {
		StabsTypeDescriptor type = parser.getType(1,1);
		assert getDataType().isEquivalent(type.getDataType());
	}

	private static DataType getDataType() {
		DataType dt = new ArrayDataType(
			IntegerDataType.dataType, 16, IntegerDataType.dataType.getLength());
		return new TypedefDataType(TEST_PATH, TYPE_NAME, dt);
	}

}
