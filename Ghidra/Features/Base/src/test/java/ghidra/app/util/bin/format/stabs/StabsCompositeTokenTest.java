package ghidra.app.util.bin.format.stabs;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;

import org.junit.Test;

public class StabsCompositeTokenTest extends AbstractStabsTest {

	private static final String STRUCTURE_TYPE_NAME = "structure_test";
	private static final String UNION_TYPE_NAME = "union_test";
	private static final String ENUM_TYPE_NAME = "enum_test";

	private static final String[] STABS = new String[]{
		TEST_FILE_NAME,
		"int:t(0,1)=r(0,1);-2147483648;2147483647;",
		"float:t(0,14)=r(0,1);4;0;",
		"char:t(0,2)=r(0,2);0;127;"
	};

	private static final String STRUCTURE_STAB = STRUCTURE_TYPE_NAME
		+":T(1,1)=s20s_int:(0,1),0,32;s_float:(0,14),32,32;s_next:(1,2)=*(1,1),64,64;;";
	private static final String UNION_STAB = UNION_TYPE_NAME
		+":T(1,2)=u20s_int:(0,1),0,32;s_float:(0,14),32,32;s_next:(1,3)=*(1,2),64,64;;";
	private static final String ENUM_STAB = ENUM_TYPE_NAME
		+":T(1,3)=eZERO:0,ONE:1,TWO:2,THREE:3,;";

	public StabsCompositeTokenTest() {
		super(STABS);
	}

	@Test
	public void parseStructureTest() throws Exception {
		StabsTypeDescriptor type = getType(STRUCTURE_STAB);
		assert getStructureType(dtm).isEquivalent(type.getDataType());
	}

	@Test
	public void parseUnionTest() throws Exception {
		StabsTypeDescriptor type = getType(UNION_STAB);
		assert getUnionType(dtm).isEquivalent(type.getDataType());
	}

	@Test
	public void parseEnumTest() throws Exception {
		StabsTypeDescriptor type = getType(ENUM_STAB);
		assert getEnumType().isEquivalent(type.getDataType());
	}

	private static DataType getStructureType(DataTypeManager dtm) {
		Structure struct = new StructureDataType(TEST_PATH, STRUCTURE_TYPE_NAME, 0, dtm);
		DataType ptr = dtm.getPointer(struct);
		struct.add(IntegerDataType.dataType, "s_int", null);
		struct.add(FloatDataType.dataType, "s_float", null);
		struct.add(ptr, "s_next", null);
		return struct;
	}

	private static DataType getUnionType(DataTypeManager dtm) {
		Union union = new UnionDataType(TEST_PATH, UNION_TYPE_NAME, dtm);
		DataType ptr = dtm.getPointer(union);
		union.add(IntegerDataType.dataType, "s_int", null);
		union.add(FloatDataType.dataType, "s_float", null);
		union.add(ptr, "s_next", null);
		return union;
	}

	private static DataType getEnumType() {
		// If anyone has something craftier than mune rename it
		// The size of the enum gets determined by the largest value
		Enum mune = new EnumDataType(TEST_PATH, ENUM_TYPE_NAME, 1);
		mune.add("ZERO", 0);
		mune.add("ONE", 1);
		mune.add("TWO", 2);
		mune.add("THREE", 3);
		return mune;
	}
	
}