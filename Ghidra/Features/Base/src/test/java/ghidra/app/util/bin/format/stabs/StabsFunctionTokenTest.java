package ghidra.app.util.bin.format.stabs;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.ShortDataType;

import org.junit.Test;

public class StabsFunctionTokenTest extends AbstractStabsTest {

	private static final CategoryPath PATH = new CategoryPath(TEST_PATH, "functions");
	private static final String TYPE_NAME = "function_test";
	private static final String CHAR_PARAM = "char_param";
	private static final String SHORT_PARAM = "short_param";
	private static final String INT_PARAM = "int_param";

	private static final String[] STABS = new String[]{
		TEST_FILE_NAME,
		"int:t(0,1)=r(0,1);-2147483648;2147483647;",
		"char:t(0,2)=r(0,2);0;127;",
		"short int:t(0,8)=r(0,8);-32768;32767;",
		TYPE_NAME+":F(0,1)", // <- (0,1) is int return type
		CHAR_PARAM+":p(0,2)",
		SHORT_PARAM+":p(0,8)",
		INT_PARAM+":p(0,1)"
	};

	public StabsFunctionTokenTest() {
		super(STABS);
	}

	@Test
	public void parseTest() throws Exception {
		StabsSymbolDescriptor token = parser.getFunctions().iterator().next();
		assert getDataType().isEquivalent(token.getDataType());
	}

	private static DataType getDataType() {
		FunctionDefinition def =
			new FunctionDefinitionDataType(PATH, TYPE_NAME);
		ParameterDefinition[] params = new ParameterDefinition[]{
			new ParameterDefinitionImpl(CHAR_PARAM, CharDataType.dataType, null),
			new ParameterDefinitionImpl(SHORT_PARAM, ShortDataType.dataType, null),
			new ParameterDefinitionImpl(INT_PARAM, IntegerDataType.dataType, null),
		};
		def.setReturnType(IntegerDataType.dataType);
		def.setArguments(params);
		return def;
	}
}
