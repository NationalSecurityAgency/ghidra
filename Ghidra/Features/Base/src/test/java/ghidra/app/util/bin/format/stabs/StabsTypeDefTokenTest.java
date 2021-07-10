package ghidra.app.util.bin.format.stabs;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.TypedefDataType;

import org.junit.Test;

public class StabsTypeDefTokenTest extends AbstractStabsTest {

	private static final String TYPE_NAME = "typedef_test";

	private static final String[] STABS = new String[]{
		TEST_FILE_NAME,
		"int:t(0,1)=r(0,1);-2147483648;2147483647;",
		TYPE_NAME+":t(1,1)=(0,1)"
	};

	public StabsTypeDefTokenTest() {
		super(STABS);
	}

	@Test
	public void parseTest() throws Exception {
		StabsTypeDescriptor type = parser.getType(1,1);
		assert type.getDataType().isEquivalent(getDataType());
	}

	private static DataType getDataType() {
		return new TypedefDataType(TEST_PATH, TYPE_NAME, IntegerDataType.dataType);
	}
}
