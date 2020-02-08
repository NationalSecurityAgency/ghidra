package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.builder.X86TypeInfoProgramBuilder;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.FundamentalTypeInfoModel;

import org.junit.Test;

public class TypeInfoTest extends GenericGccRttiTest {

	@Test
	public void validationTest() throws Exception {
		X86TypeInfoProgramBuilder builder = new X86TypeInfoProgramBuilder();
		for (TypeInfo type : builder.getTypeInfoList()) {
			if (!(type instanceof FundamentalTypeInfoModel)) {
				// Invalid dynamic relocations prevent fundamentals from being valid
				assert type.getDataType() != null;
			}
		}
	}
}
