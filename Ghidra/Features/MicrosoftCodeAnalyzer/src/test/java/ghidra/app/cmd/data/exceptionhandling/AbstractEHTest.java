/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.cmd.data.exceptionhandling;

import ghidra.app.cmd.data.AbstractCreateDataTypeModelTest;
import ghidra.app.cmd.data.rtti.RttiUtil;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;

public class AbstractEHTest extends AbstractCreateDataTypeModelTest {


	protected void setupV1FuncInfo32(ProgramBuilder builder, long address, int magicNum,
			int unwindCount, String unwindAddress, int tryCount, String tryAddress, int ipCount,
			String ipAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address magicNumCompAddr = builder.addr(address);
		Address unwindCountCompAddr = builder.addr(address + 4);
		Address unwindCompAddr = builder.addr(address + 8);
		Address tryCountCompAddr = builder.addr(address + 12);
		Address tryCompAddr = builder.addr(address + 16);
		Address ipCountCompAddr = builder.addr(address + 20);
		Address ipCompAddr = builder.addr(address + 24);
		builder.setBytes(magicNumCompAddr.toString(), getIntAsByteString(magicNum, bigEndian));
		builder.setBytes(unwindCountCompAddr.toString(),
			getIntAsByteString(unwindCount, bigEndian));
		builder.setBytes(unwindCompAddr.toString(),
			getHexAddress32AsByteString(unwindAddress, bigEndian));
		builder.setBytes(tryCountCompAddr.toString(), getIntAsByteString(tryCount, bigEndian));
		builder.setBytes(tryCompAddr.toString(),
			getHexAddress32AsByteString(tryAddress, bigEndian));
		builder.setBytes(ipCountCompAddr.toString(), getIntAsByteString(ipCount, bigEndian));
		builder.setBytes(ipCompAddr.toString(), getHexAddress32AsByteString(ipAddress, bigEndian));
		setupDummy32TypeInfo(builder);
	}

	protected void setupV2FuncInfo32(ProgramBuilder builder, long address, int magicNum,
			int unwindCount, String unwindAddress, int tryCount, String tryAddress, int ipCount,
			String ipAddress, String typeListAddress) throws Exception {
		setupV1FuncInfo32(builder, address, magicNum, unwindCount, unwindAddress, tryCount,
			tryAddress, ipCount, ipAddress);
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address typeListCompAddr = builder.addr(address + 28);
		builder.setBytes(typeListCompAddr.toString(),
			getHexAddress32AsByteString(typeListAddress, bigEndian));
	}

	protected void setupV3FuncInfo32(ProgramBuilder builder, long address, int magicNum,
			int unwindCount, String unwindAddress, int tryCount, String tryAddress, int ipCount,
			String ipAddress, String typeListAddress, int ehFlags) throws Exception {
		setupV2FuncInfo32(builder, address, magicNum, unwindCount, unwindAddress, tryCount,
			tryAddress, ipCount, ipAddress, typeListAddress);
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address ehFlagsCompAddr = builder.addr(address + 32);
		builder.setBytes(ehFlagsCompAddr.toString(), getIntAsByteString(ehFlags, bigEndian));
	}

	protected void setupV1FuncInfo64(ProgramBuilder builder, long address, int magicNum,
			int unwindCount, String unwindAddress, int tryCount, String tryAddress, int ipCount,
			String ipAddress, int unwindHelpDisplacement) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address magicNumCompAddr = builder.addr(address);
		Address unwindCountCompAddr = builder.addr(address + 4);
		Address unwindCompAddr = builder.addr(address + 8);
		Address tryCountCompAddr = builder.addr(address + 12);
		Address tryCompAddr = builder.addr(address + 16);
		Address ipCountCompAddr = builder.addr(address + 20);
		Address ipCompAddr = builder.addr(address + 24);
		Address unwindHelpCompAddr = builder.addr(address + 28);
		builder.setBytes(magicNumCompAddr.toString(), getIntAsByteString(magicNum, bigEndian));
		builder.setBytes(unwindCountCompAddr.toString(),
			getIntAsByteString(unwindCount, bigEndian));
		builder.setBytes(unwindCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, unwindAddress, bigEndian));
		builder.setBytes(tryCountCompAddr.toString(), getIntAsByteString(tryCount, bigEndian));
		builder.setBytes(tryCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, tryAddress, bigEndian));
		builder.setBytes(ipCountCompAddr.toString(), getIntAsByteString(ipCount, bigEndian));
		builder.setBytes(ipCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, ipAddress, bigEndian));
		builder.setBytes(unwindHelpCompAddr.toString(),
			getIntAsByteString(unwindHelpDisplacement, bigEndian));
		setupDummy64TypeInfo(builder);
	}

	protected void setupV2FuncInfo64(ProgramBuilder builder, long address, int magicNum,
			int unwindCount, String unwindAddress, int tryCount, String tryAddress, int ipCount,
			String ipAddress, int unwindHelpDisplacement, String typeListAddress) throws Exception {
		setupV1FuncInfo64(builder, address, magicNum, unwindCount, unwindAddress, tryCount,
			tryAddress, ipCount, ipAddress, unwindHelpDisplacement);
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address typeListCompAddr = builder.addr(address + 32);
		builder.setBytes(typeListCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, typeListAddress, bigEndian));
	}

	protected void setupV3FuncInfo64(ProgramBuilder builder, long address, int magicNum,
			int unwindCount, String unwindAddress, int tryCount, String tryAddress, int ipCount,
			String ipAddress, int unwindHelpDisplacement, String typeListAddress, int ehFlags)
			throws Exception {
		setupV2FuncInfo64(builder, address, magicNum, unwindCount, unwindAddress, tryCount,
			tryAddress, ipCount, ipAddress, unwindHelpDisplacement, typeListAddress);
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address ehFlagsCompAddr = builder.addr(address + 36);
		builder.setBytes(ehFlagsCompAddr.toString(), getIntAsByteString(ehFlags, bigEndian));
	}

	protected void setupUnwind32(ProgramBuilder builder, long address, int toState,
			String actionAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address toStateCompAddr = builder.addr(address);
		Address actionCompAddr = builder.addr(address + 4);
		builder.setBytes(toStateCompAddr.toString(), getIntAsByteString(toState, bigEndian));
		builder.setBytes(actionCompAddr.toString(),
			getHexAddress32AsByteString(actionAddress, bigEndian));
	}

	protected void setupUnwind64(ProgramBuilder builder, long address, int toState,
			String actionAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address toStateCompAddr = builder.addr(address);
		Address actionCompAddr = builder.addr(address + 4);
		builder.setBytes(toStateCompAddr.toString(), getIntAsByteString(toState, bigEndian));
		builder.setBytes(actionCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, actionAddress, bigEndian));
	}

	protected void setupTryBlock32(ProgramBuilder builder, long address, int tryLow, int tryHigh,
			int catchHigh, int handlerCount, String handlerAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address tryLowCompAddr = builder.addr(address);
		Address tryHighCompAddr = builder.addr(address + 4);
		Address catchHighCompAddr = builder.addr(address + 8);
		Address handlerCountCompAddr = builder.addr(address + 12);
		Address handlerCompAddr = builder.addr(address + 16);
		builder.setBytes(tryLowCompAddr.toString(), getIntAsByteString(tryLow, bigEndian));
		builder.setBytes(tryHighCompAddr.toString(), getIntAsByteString(tryHigh, bigEndian));
		builder.setBytes(catchHighCompAddr.toString(), getIntAsByteString(catchHigh, bigEndian));
		builder.setBytes(handlerCountCompAddr.toString(),
			getIntAsByteString(handlerCount, bigEndian));
		builder.setBytes(handlerCompAddr.toString(),
			getHexAddress32AsByteString(handlerAddress, bigEndian));
	}

	protected void setupTryBlock64(ProgramBuilder builder, long address, int tryLow, int tryHigh,
			int catchHigh, int handlerCount, String handlerAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address tryLowCompAddr = builder.addr(address);
		Address tryHighCompAddr = builder.addr(address + 4);
		Address catchHighCompAddr = builder.addr(address + 8);
		Address handlerCountCompAddr = builder.addr(address + 12);
		Address handlerCompAddr = builder.addr(address + 16);
		builder.setBytes(tryLowCompAddr.toString(), getIntAsByteString(tryLow, bigEndian));
		builder.setBytes(tryHighCompAddr.toString(), getIntAsByteString(tryHigh, bigEndian));
		builder.setBytes(catchHighCompAddr.toString(), getIntAsByteString(catchHigh, bigEndian));
		builder.setBytes(handlerCountCompAddr.toString(),
			getIntAsByteString(handlerCount, bigEndian));
		builder.setBytes(handlerCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, handlerAddress, bigEndian));
	}

	protected void setupIPToState32(ProgramBuilder builder, long address, int ip, int state)
			throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address ipCompAddr = builder.addr(address);
		Address stateCompAddr = builder.addr(address + 4);
		builder.setBytes(ipCompAddr.toString(), getIntAsByteString(ip, bigEndian));
		builder.setBytes(stateCompAddr.toString(), getIntAsByteString(state, bigEndian));
	}

	protected void setupIPToState64(ProgramBuilder builder, long address, String ipAddress,
			int state) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address ipCompAddr = builder.addr(address);
		Address stateCompAddr = builder.addr(address + 4);
		builder.setBytes(ipCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, ipAddress, bigEndian));
		builder.setBytes(stateCompAddr.toString(), getIntAsByteString(state, bigEndian));
	}

	protected void setupCatchHandler32(ProgramBuilder builder, long address, int adjectives,
			String typeAddress, int dispCatchObj, String catchHandlerAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address adjectivesCompAddr = builder.addr(address);
		Address typeAddressCompAddr = builder.addr(address + 4);
		Address dispCatchObjCompAddr = builder.addr(address + 8);
		Address catchHandlerCompAddr = builder.addr(address + 12);
		builder.setBytes(adjectivesCompAddr.toString(), getIntAsByteString(adjectives, bigEndian));
		builder.setBytes(typeAddressCompAddr.toString(),
			getHexAddress32AsByteString(typeAddress, bigEndian));
		builder.setBytes(dispCatchObjCompAddr.toString(),
			getIntAsByteString(dispCatchObj, bigEndian));
		builder.setBytes(catchHandlerCompAddr.toString(),
			getHexAddress32AsByteString(catchHandlerAddress, bigEndian));
	}

	protected void setupCatchHandler64(ProgramBuilder builder, long address, int adjectives,
			String typeAddress, int dispCatchObj, String catchHandlerAddress, int dispFrame)
			throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address adjectivesCompAddr = builder.addr(address);
		Address typeAddressCompAddr = builder.addr(address + 4);
		Address dispCatchObjCompAddr = builder.addr(address + 8);
		Address catchHandlerCompAddr = builder.addr(address + 12);
		Address dispFrameCompAddr = builder.addr(address + 16);
		builder.setBytes(adjectivesCompAddr.toString(), getIntAsByteString(adjectives, bigEndian));
		builder.setBytes(typeAddressCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, typeAddress, bigEndian));
		builder.setBytes(dispCatchObjCompAddr.toString(),
			getIntAsByteString(dispCatchObj, bigEndian));
		builder.setBytes(catchHandlerCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, catchHandlerAddress, bigEndian));
		builder.setBytes(dispFrameCompAddr.toString(), getIntAsByteString(dispFrame, bigEndian));
	}

	protected void setupTypeDescriptor32(ProgramBuilder builder, long address, String tableAddress,
			String spareAddress, String name) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address tableAddressCompAddr = builder.addr(address);
		Address spareAddressCompAddr = builder.addr(address + 4);
		Address nameCompAddr = builder.addr(address + 8);
		builder.setBytes(tableAddressCompAddr.toString(),
			getHexAddress32AsByteString(tableAddress, bigEndian));
		builder.setBytes(spareAddressCompAddr.toString(),
			getHexAddress32AsByteString(spareAddress, bigEndian));
		builder.setBytes(nameCompAddr.toString(), name.getBytes());
	}

	protected void setupTypeDescriptor64(ProgramBuilder builder, long address, String tableAddress,
			String spareAddress, String name) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address tableAddressCompAddr = builder.addr(address);
		Address spareAddressCompAddr = builder.addr(address + 8);
		Address nameCompAddr = builder.addr(address + 16);
		builder.setBytes(tableAddressCompAddr.toString(),
			getHexAddress64AsByteString(tableAddress, bigEndian));
		builder.setBytes(spareAddressCompAddr.toString(),
			getHexAddress64AsByteString(spareAddress, bigEndian));
		builder.setBytes(nameCompAddr.toString(), name.getBytes());
	}

	protected void setupTypeList32(ProgramBuilder builder, long address, int handlerCount,
			String handlerAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address handlerCountCompAddr = builder.addr(address);
		Address handlerAddressCompAddr = builder.addr(address + 4);
		// HandlerType count in list
		builder.setBytes(handlerCountCompAddr.toString(),
			getIntAsByteString(handlerCount, bigEndian));
		// Address of list of HandlerType records.
		builder.setBytes(handlerAddressCompAddr.toString(),
			getHexAddress32AsByteString(handlerAddress, bigEndian));
	}

	protected void setupTypeList64(ProgramBuilder builder, long address, int handlerCount,
			String handlerAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address handlerCountCompAddr = builder.addr(address);
		Address handlerAddressCompAddr = builder.addr(address + 4);
		// HandlerType count in list
		builder.setBytes(handlerCountCompAddr.toString(),
			getIntAsByteString(handlerCount, bigEndian));
		// Ibo32 of list of HandlerType records.
		builder.setBytes(handlerAddressCompAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, handlerAddress, bigEndian));
	}

	protected void setupV1FuncInfo32CompleteFlow(ProgramBuilder builder) throws Exception {
		// FuncInfo
		setupV1FuncInfo32(builder, 0x01003340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 3,
			"0x01003368", 2, "0x01003380", 4, "0x010033d0"); // 28 bytes
		setupDummy32TypeInfo(builder);
		setupCompleteFlow32NoESTypeList(builder);
	}

	protected void setupV2FuncInfo32CompleteFlow(ProgramBuilder builder) throws Exception {
		// FuncInfo
		setupV2FuncInfo32(builder, 0x01003340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, 3,
			"0x01003368", 2, "0x01003380", 4, "0x010033d0", "0x010033f0"); // 32 bytes
		setupDummy32TypeInfo(builder);
		setupCompleteFlow32(builder);
	}

	protected void setupV3FuncInfo32CompleteFlow(ProgramBuilder builder) throws Exception {
		// FuncInfo
		setupV3FuncInfo32(builder, 0x01003340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 3,
			"0x01003368", 2, "0x01003380", 4, "0x010033d0", "0x010033f0", 0x1); // 36 bytes
		setupDummy32TypeInfo(builder);
		setupCompleteFlow32(builder);
	}

	private void setupCompleteFlow32(ProgramBuilder builder) throws Exception {
		setupCompleteFlow32NoESTypeList(builder);

		// ESTypeList
		setupTypeList32(builder, 0x010033f0, 2, "0x01001800");
		setupCatchHandler32(builder, 0x01001800, 0x0, "0x01005400", 0x32, "0x01001120"); // 16 bytes
		setupCatchHandler32(builder, 0x01001810, 0x4, "0x00000000", 0, "0x01001140"); // 16 bytes
		setupCode32Bytes(builder, "0x01001120");
		setupCode32Instructions(builder, "0x01001140");
	}

	private void setupCompleteFlow32NoESTypeList(ProgramBuilder builder) throws Exception {
		// UnwindMap
		setupUnwind32(builder, 0x01003368, 0xffffffff, "0x01001200"); // 8 bytes
		setupUnwind32(builder, 0x01003370, 0x0, "0x01001214"); // 8 bytes
		setupUnwind32(builder, 0x01003378, 0x1, "0x01001230"); // 8 bytes
		// TryBlockMap
		setupTryBlock32(builder, 0x01003380, 2, 2, 3, 2, "0x010033a8"); // 20 bytes
		setupTryBlock32(builder, 0x01003394, 0, 0, 1, 1, "0x010032a0"); // 20 bytes
		// CatchHandlerMap
		setupCatchHandler32(builder, 0x010033a8, 0x3, "0x01005400", 5, "0x01001260"); // 16 bytes
		setupCatchHandler32(builder, 0x010033b8, 0x40, "0x00000000", 0, "0x01001280"); // 16 bytes
		setupCatchHandler32(builder, 0x010032a0, 0x5, "0x01005428", 4, "0x010012a0"); // 16 bytes
		// IPToStateMap
		setupIPToState32(builder, 0x010033d0, 0x01001200, 0xffffffff); // 8 bytes
		setupIPToState32(builder, 0x010033d8, 0x01001300, 0); // 8 bytes
		setupIPToState32(builder, 0x010033e0, 0x01001400, 1); // 8 bytes
		setupIPToState32(builder, 0x010033e8, 0x01001500, 0); // 8 bytes

		// UnwindCode1
		// UnwindCode2
		// UnwindCode3
		setupCode32Bytes(builder, "0x01001200");
		setupCode32Instructions(builder, "0x01001214");
		setupCode32Bytes(builder, "0x01001230");

		// CatchCode1ForTry1
		// CatchCode2ForTry1
		// CatchCode1ForTry2
		setupCode32Bytes(builder, "0x01001260");
		setupCode32Instructions(builder, "0x01001280");
		setupCode32Bytes(builder, "0x010012a0");

		// TypeDescriptor 1
		// TypeDescriptor 2
		setupTypeDescriptor32(builder, 0x01005400, "0x01003500", "0x00000000", "NotReachableError"); // 34 bytes + 6 align = 40
		setupTypeDescriptor32(builder, 0x01005428, "0x01003540", "0x00000000",
			"DataUnavailableError"); // 37 bytes + 3 align = 40
	}

	protected void checkFuncInfoV1Data(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "FuncInfo",
			new String[] { "magicNumber_and_bbtFlags", "maxState", "pUnwindMap", "nTryBlocks",
				"pTryBlockMap", "nIPMapEntries", "pIPToStateMap" },
			28);
	}

	protected void checkFuncInfoV2Data(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "FuncInfo",
			new String[] { "magicNumber_and_bbtFlags", "maxState", "pUnwindMap", "nTryBlocks",
				"pTryBlockMap", "nIPMapEntries", "pIPToStateMap", "pESTypeList" },
			32);
	}

	protected void checkFuncInfoV3Data(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "FuncInfo",
			new String[] { "magicNumber_and_bbtFlags", "maxState", "pUnwindMap", "nTryBlocks",
				"pTryBlockMap", "nIPMapEntries", "pIPToStateMap", "pESTypeList", "EHFlags" },
			36);
	}

	protected void checkUnwindMapData32(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "UnwindMapEntry",
			new String[] { "toState", "action" }, 8);
	}

	protected void checkTryBlockData32(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "TryBlockMapEntry",
			new String[] { "tryLow", "tryHigh", "catchHigh", "nCatches", "pHandlerArray" }, 20);
	}

	protected void checkCatchHandlerData32(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "HandlerType",
			new String[] { "adjectives", "pType", "dispCatchObj", "addressOfHandler" }, 16);
	}

	protected void checkIPToStateMapData32(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "IPToStateMapEntry",
			new String[] { "Ip", "state" }, 8);
	}

	protected void checkESTypeListData32(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "ESTypeList",
			new String[] { "nCount", "pTypeArray" }, 8);
	}

	protected void setupV1FuncInfo64CompleteFlow(ProgramBuilder builder) throws Exception {
		// FuncInfo
		setupV1FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200);
		setupDummy64TypeInfo(builder);
		setupCompleteFlow64NoESTypeList(builder);
	}

	protected void setupV2FuncInfo64CompleteFlow(ProgramBuilder builder) throws Exception {
		// FuncInfo
		setupV2FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200, "0x1010033f0");
		setupDummy64TypeInfo(builder);
		setupCompleteFlow64(builder);
	}

	protected void setupV3FuncInfo64CompleteFlow(ProgramBuilder builder) throws Exception {
		// FuncInfo
		setupV3FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200, "0x1010033f0", 0x1);
		setupDummy64TypeInfo(builder);
		setupCompleteFlow64(builder);
	}

	private void setupCompleteFlow64(ProgramBuilder builder) throws Exception {
		setupCompleteFlow64NoESTypeList(builder);

		// ESTypeList
		setupTypeList64(builder, 0x1010033f0L, 2, "0x101001800");
		setupCatchHandler64(builder, 0x101001800L, 0x0, "0x101005400", 0x32, "0x101001120", 0x58); // 20 bytes
		setupCatchHandler64(builder, 0x101001814L, 0x4, "0x101000000", 0, "0x101001140", 0x58); // 20 bytes
		setupCode64Bytes(builder, "0x101001120");
		setupCode64Instructions(builder, "0x101001140");
	}

	private void setupCompleteFlow64NoESTypeList(ProgramBuilder builder) throws Exception {
		// UnwindMap
		setupUnwind64(builder, 0x101003368L, 0xffffffff, "0x101001200"); // 8 bytes
		setupUnwind64(builder, 0x101003370L, 0x0, "0x101001214"); // 8 bytes
		setupUnwind64(builder, 0x101003378L, 0x1, "0x101001230"); // 8 bytes
		// TryBlockMap
		setupTryBlock64(builder, 0x101003380L, 2, 2, 3, 2, "0x1010033a8"); // 20 bytes
		setupTryBlock64(builder, 0x101003394L, 0, 0, 1, 1, "0x1010032a0"); // 20 bytes
		// CatchHandlerMap
		setupCatchHandler64(builder, 0x1010033a8L, 0x3, "0x101005400", 5, "0x101001260", 0x58); // 20 bytes
		setupCatchHandler64(builder, 0x1010033bcL, 0x40, "0x101000000", 0, "0x101001280", 0x58); // 20 bytes
		setupCatchHandler64(builder, 0x1010032a0L, 0x5, "0x101005428", 4, "0x1010012a0", 0x58); // 20 bytes
		// IPToStateMap
		setupIPToState64(builder, 0x1010033d0L, "0x101001200", 0xffffffff); // 8 bytes
		setupIPToState64(builder, 0x1010033d8L, "0x101001300", 0); // 8 bytes
		setupIPToState64(builder, 0x1010033e0L, "0x101001400", 1); // 8 bytes
		setupIPToState64(builder, 0x1010033e8L, "0x101001500", 0); // 8 bytes

		// UnwindCode1
		// UnwindCode2
		// UnwindCode3
		setupCode64Bytes(builder, "0x101001200");
		setupCode64Instructions(builder, "0x101001214");
		setupCode64Bytes(builder, "0x101001230");

		// CatchCode1ForTry1
		// CatchCode2ForTry1
		// CatchCode1ForTry2
		setupCode64Bytes(builder, "0x101001260");
		setupCode64Instructions(builder, "0x101001280");
		setupCode64Bytes(builder, "0x1010012a0");

		// TypeDescriptor 1
		// TypeDescriptor 2
		setupTypeDescriptor64(builder, 0x101005400L, "0x0000000101003500", "0x0000000000000000",
			"NotReachableError"); // 34 bytes + 6 align = 40
		setupTypeDescriptor64(builder, 0x101005428L, "0x0000000101003540", "0x0000000000000000",
			"DataUnavailableError"); // 37 bytes + 3 align = 40
	}

	protected void checkFuncInfoV1Data64(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "FuncInfo",
			new String[] { "magicNumber_and_bbtFlags", "maxState", "dispUnwindMap", "nTryBlocks",
				"dispTryBlockMap", "nIPMapEntries", "dispIPToStateMap", "dispUnwindHelp" },
			32);
	}

	protected void checkFuncInfoV2Data64(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "FuncInfo",
			new String[] { "magicNumber_and_bbtFlags", "maxState", "dispUnwindMap", "nTryBlocks",
				"dispTryBlockMap", "nIPMapEntries", "dispIPToStateMap", "dispUnwindHelp",
				"dispESTypeList" },
			36);
	}

	protected void checkFuncInfoV3Data64(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "FuncInfo",
			new String[] { "magicNumber_and_bbtFlags", "maxState", "dispUnwindMap", "nTryBlocks",
				"dispTryBlockMap", "nIPMapEntries", "dispIPToStateMap", "dispUnwindHelp",
				"dispESTypeList", "EHFlags" },
			40);
	}

	protected void checkUnwindMapData64(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "UnwindMapEntry",
			new String[] { "toState", "action" }, 8);
	}

	protected void checkTryBlockData64(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "TryBlockMapEntry",
			new String[] { "tryLow", "tryHigh", "catchHigh", "nCatches", "dispHandlerArray" }, 20);
	}

	protected void checkCatchHandlerData64(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "HandlerType",
			new String[] { "adjectives", "dispType", "dispCatchObj", "dispOfHandler", "dispFrame" },
			20);
	}

	protected void checkIPToStateMapData64(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "IPToStateMapEntry",
			new String[] { "Ip", "state" }, 8);
	}

	protected void checkESTypeListData64(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "ESTypeList",
			new String[] { "nCount", "dispTypeArray" }, 8);
	}

}
