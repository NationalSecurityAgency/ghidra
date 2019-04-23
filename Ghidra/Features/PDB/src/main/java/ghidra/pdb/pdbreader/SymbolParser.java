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
package ghidra.pdb.pdbreader;

import java.util.HashSet;
import java.util.Set;

import ghidra.pdb.*;
import ghidra.pdb.pdbreader.symbol.*;

/**
 * Parser for detecting the parsing the appropriate Symbol structures ({@link AbstractMsSymbol}) in
 *  the PDB.
 */
public class SymbolParser {

	//==============================================================================================
	// Internals
	//==============================================================================================
	private AbstractPdb pdb;

	/**
	 * This list indicates which Symbol Types ({@link AbstractMsSymbol}) have been seen in real
	 *  data, giving us some confidence as to whether we have parsed them OK or not.  We can set
	 *  a break point in the method containing the switch statement to trigger whenever we find a
	 *  symbol type not in this list.
	 */
	private static Set<Integer> symbolTypesSeen = new HashSet<>(); //temporary for filling in types
	private Set<Integer> newSymbolTypesSeen = new HashSet<>();
	static {
		symbolTypesSeen.add(0x0001);
//		symbolTypesSeen.add(0x0002);
		symbolTypesSeen.add(0x0003);
//		symbolTypesSeen.add(0x0004);
//		symbolTypesSeen.add(0x0005);
		symbolTypesSeen.add(0x0006);
//		symbolTypesSeen.add(0x0007);
//		symbolTypesSeen.add(0x0008);
//		symbolTypesSeen.add(0x0009);
//		symbolTypesSeen.add(0x000a);
//		symbolTypesSeen.add(0x000b);
//		symbolTypesSeen.add(0x000c);
//		symbolTypesSeen.add(0x000d);
//		symbolTypesSeen.add(0x000e);

//		symbolTypesSeen.add(0x0100);
//		symbolTypesSeen.add(0x0101);
//		symbolTypesSeen.add(0x0102);
//		symbolTypesSeen.add(0x0103);
//		symbolTypesSeen.add(0x0104);
//		symbolTypesSeen.add(0x0105);
//		symbolTypesSeen.add(0x0106);
//		symbolTypesSeen.add(0x0107);
//		symbolTypesSeen.add(0x0108);
//		symbolTypesSeen.add(0x0109);
//		symbolTypesSeen.add(0x010a);
//		symbolTypesSeen.add(0x010b);
//		symbolTypesSeen.add(0x010c);

//		symbolTypesSeen.add(0x0200);
//		symbolTypesSeen.add(0x0201);
//		symbolTypesSeen.add(0x0202);
//		symbolTypesSeen.add(0x0203);
//		symbolTypesSeen.add(0x0204);
//		symbolTypesSeen.add(0x0205);
//		symbolTypesSeen.add(0x0206);
//		symbolTypesSeen.add(0x0207);
//		symbolTypesSeen.add(0x0208);
//		symbolTypesSeen.add(0x0209);
//		symbolTypesSeen.add(0x020a);
//		symbolTypesSeen.add(0x020b);
//		symbolTypesSeen.add(0x020c);
//		symbolTypesSeen.add(0x020d);
//		symbolTypesSeen.add(0x020e);
//		symbolTypesSeen.add(0x020f);

//		symbolTypesSeen.add(0x0300);
//		symbolTypesSeen.add(0x0301);

//		symbolTypesSeen.add(0x0400);
//		symbolTypesSeen.add(0x0401);
//		symbolTypesSeen.add(0x0402);
//		symbolTypesSeen.add(0x0403);
		symbolTypesSeen.add(0x0404);

//		symbolTypesSeen.add(0x1001);
		symbolTypesSeen.add(0x1002);
//		symbolTypesSeen.add(0x1003);
//		symbolTypesSeen.add(0x1004);
//		symbolTypesSeen.add(0x1005);
//		symbolTypesSeen.add(0x1006);
//		symbolTypesSeen.add(0x1007);
//		symbolTypesSeen.add(0x1008);
//		symbolTypesSeen.add(0x1009);
//		symbolTypesSeen.add(0x100a);
//		symbolTypesSeen.add(0x100b);
//		symbolTypesSeen.add(0x100c);
//		symbolTypesSeen.add(0x100d);
//		symbolTypesSeen.add(0x100e);
//		symbolTypesSeen.add(0x100f);
//		symbolTypesSeen.add(0x1010);
//		symbolTypesSeen.add(0x1011);
		symbolTypesSeen.add(0x1012);
//		symbolTypesSeen.add(0x1013);
//		symbolTypesSeen.add(0x1014);
//		symbolTypesSeen.add(0x1015);
//		symbolTypesSeen.add(0x1016);
//		symbolTypesSeen.add(0x1017);
//		symbolTypesSeen.add(0x1018);
//		symbolTypesSeen.add(0x1019);
//		symbolTypesSeen.add(0x101a);
//		symbolTypesSeen.add(0x101b);
//		symbolTypesSeen.add(0x101c);
//		symbolTypesSeen.add(0x101d);
//		symbolTypesSeen.add(0x101e);
//		symbolTypesSeen.add(0x101f);
//		symbolTypesSeen.add(0x1020);
//		symbolTypesSeen.add(0x1021);
//		symbolTypesSeen.add(0x1022);
//		symbolTypesSeen.add(0x1023);
//		symbolTypesSeen.add(0x1024);
//		symbolTypesSeen.add(0x1025);
//		symbolTypesSeen.add(0x1026);
//		symbolTypesSeen.add(0x1027);
//		symbolTypesSeen.add(0x1028);
//		symbolTypesSeen.add(0x1029);

		symbolTypesSeen.add(0x1101);
		symbolTypesSeen.add(0x1102);
		symbolTypesSeen.add(0x1103);
//		symbolTypesSeen.add(0x1104);
		symbolTypesSeen.add(0x1105);
		symbolTypesSeen.add(0x1106);
		symbolTypesSeen.add(0x1107);
		symbolTypesSeen.add(0x1108);
//		symbolTypesSeen.add(0x1109);
//		symbolTypesSeen.add(0x110a);
		symbolTypesSeen.add(0x110b);
		symbolTypesSeen.add(0x110c);
		symbolTypesSeen.add(0x110d);
		symbolTypesSeen.add(0x110e);
		symbolTypesSeen.add(0x110f);
		symbolTypesSeen.add(0x1110);
		symbolTypesSeen.add(0x1111);
//		symbolTypesSeen.add(0x1112);
//		symbolTypesSeen.add(0x1113);
		symbolTypesSeen.add(0x1114);
		symbolTypesSeen.add(0x1115);
		symbolTypesSeen.add(0x1116);
//		symbolTypesSeen.add(0x1117);
//		symbolTypesSeen.add(0x1118);
//		symbolTypesSeen.add(0x1119);
//		symbolTypesSeen.add(0x111a);
//		symbolTypesSeen.add(0x111b);
//		symbolTypesSeen.add(0x111c);
//		symbolTypesSeen.add(0x111d);
//		symbolTypesSeen.add(0x111e);
//		symbolTypesSeen.add(0x111f);
		symbolTypesSeen.add(0x1120);
//		symbolTypesSeen.add(0x1121);
//		symbolTypesSeen.add(0x1122);
//		symbolTypesSeen.add(0x1123);
		symbolTypesSeen.add(0x1124);
		symbolTypesSeen.add(0x1125);
//		symbolTypesSeen.add(0x1126);
		symbolTypesSeen.add(0x1127);
//		symbolTypesSeen.add(0x1128);
		symbolTypesSeen.add(0x1129);
		symbolTypesSeen.add(0x112a);
//		symbolTypesSeen.add(0x112b);
		symbolTypesSeen.add(0x112c);
		symbolTypesSeen.add(0x112d);
//		symbolTypesSeen.add(0x112e);
//		symbolTypesSeen.add(0x112f);
//		symbolTypesSeen.add(0x1130);
//		symbolTypesSeen.add(0x1131);
		symbolTypesSeen.add(0x1132);
//		symbolTypesSeen.add(0x1133);
//		symbolTypesSeen.add(0x1134);
//		symbolTypesSeen.add(0x1135);
		symbolTypesSeen.add(0x1136);
		symbolTypesSeen.add(0x1137);
		symbolTypesSeen.add(0x1138);
		symbolTypesSeen.add(0x1139);
		symbolTypesSeen.add(0x113a);
//		symbolTypesSeen.add(0x113b);
		symbolTypesSeen.add(0x113c);
		symbolTypesSeen.add(0x113d);
		symbolTypesSeen.add(0x113e);
//		symbolTypesSeen.add(0x113f);
//		symbolTypesSeen.add(0x1140);
		symbolTypesSeen.add(0x1141);
		symbolTypesSeen.add(0x1142);
		symbolTypesSeen.add(0x1143);
		symbolTypesSeen.add(0x1144);
		symbolTypesSeen.add(0x1145);
//		symbolTypesSeen.add(0x1146);
//		symbolTypesSeen.add(0x1147);
//		symbolTypesSeen.add(0x1148);
//		symbolTypesSeen.add(0x1149);
//		symbolTypesSeen.add(0x114a);
//		symbolTypesSeen.add(0x114b);
		symbolTypesSeen.add(0x114c);
		symbolTypesSeen.add(0x114d);
		symbolTypesSeen.add(0x114e);
//		symbolTypesSeen.add(0x114f);
//		symbolTypesSeen.add(0x1150);
//		symbolTypesSeen.add(0x1151);
//		symbolTypesSeen.add(0x1152);
		symbolTypesSeen.add(0x1153);
//		symbolTypesSeen.add(0x1154);
//		symbolTypesSeen.add(0x1155);
//		symbolTypesSeen.add(0x1156);
//		symbolTypesSeen.add(0x1157);
//		symbolTypesSeen.add(0x1158);
		symbolTypesSeen.add(0x1159);
		symbolTypesSeen.add(0x115a);
//		symbolTypesSeen.add(0x115b);
//		symbolTypesSeen.add(0x115c);
//		symbolTypesSeen.add(0x115d);
		symbolTypesSeen.add(0x115e);
//		symbolTypesSeen.add(0x115f);
//		symbolTypesSeen.add(0x1169);
//		symbolTypesSeen.add(0x1161);
//		symbolTypesSeen.add(0x1162);
//		symbolTypesSeen.add(0x1163);
//		symbolTypesSeen.add(0x1164);
//		symbolTypesSeen.add(0x1165);
//      There is not documentation for anything beyond 0x1165.
//		symbolTypesSeen.add(0x1166);
		symbolTypesSeen.add(0x1167);
		symbolTypesSeen.add(0x1168);
	}

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns the Symbols to be parsed.
	 */
	public SymbolParser(AbstractPdb pdb) {
		this.pdb = pdb;
	}

	/**
	 * Returns a list of Symbol IDs that we have not seen in real data while testing.
	 * @return {@link String} of pretty output message.
	 */
	public String getNewSymbolTypesLog() {
		StringBuilder builder = new StringBuilder();
		DelimiterState ds = new DelimiterState("New Symbol IDs Seen: ", ",");
		for (Integer val : newSymbolTypesSeen) {
			builder.append(ds.out(true, String.format("0x04X, ", val)));
		}
		return builder.toString();
	}

	/**
	 * Deserializes an {@link AbstractMsSymbol} from the {@link PdbByteReader} and returns it.
	 * @param reader {@link PdbByteReader} from which to deserialize the symbol record.
	 * @return {@link AbstractMsSymbol} that was parsed.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractMsSymbol parse(PdbByteReader reader) throws PdbException {
		int symbolTypeId = reader.parseUnsignedShortVal();
		AbstractMsSymbol symbol;
		try {
			symbol = parseRecord(symbolTypeId, reader);
		}
		catch (PdbException e) {
			symbol = new BadMsSymbol(pdb, symbolTypeId);
		}
		return symbol;
	}

	/**
	 * Deserializes an {@link AbstractMsSymbol} from the {@link PdbByteReader} and returns it.
	 * @param reader {@link PdbByteReader} from which to deserialize the symbol record.
	 * @return {@link AbstractMsSymbol} that was parsed.
	 * @throws PdbException upon error parsing a field.
	 */
	private AbstractMsSymbol parseRecord(int symbolTypeId, PdbByteReader reader)
			throws PdbException {
//		//System.out.println(reader.dump(0x200));
//		// DO NOT REMOVE
//		// The following code is for developmental investigations;
//		//  set break point on "int a = 1;" instead of a
//		//  conditional break point.
//		if (symbolTypeId == 0x204) {
//			int a = 1;
//			a = a + 1;
//		}
//		// DO NOT REMOVE
//		// The following code is for developmental investigations;
//		//  set break point on "int a = 1;" instead of a
//		//  conditional break point.
//		if (symbolTypeId >= 0x1000 && symbolTypeId < 0x1100) {
//			if (symbolTypeId != 0x1012) {
//				int a = 1;
//				a = a + 1;
//			}
//		}
		if (!symbolTypesSeen.contains(symbolTypeId)) {
			newSymbolTypesSeen.add(symbolTypeId);
//			//System.out.println(String.format("Symbol Type not seen before: %04x", symbolTypeId));
//			// DO NOT REMOVE
//			// Set break point on instruction below to trigger on any symbol types that we
//			//  have not seen in real data.  Then step through the parsing for these new
//			//  symbol types to confirm that our parsing and the real data agree.  Also, comment
//			//  in the line above to show the ID for this type whenever desired.
//			int a = 1;
//			a = a + 1;
		}

		AbstractMsSymbol symbol = null;
		switch (symbolTypeId) {
			// 0x0000 block
			case CompileFlagsMsSymbol.PDB_ID:
				symbol = new CompileFlagsMsSymbol(pdb, reader);
//				System.out.println(symbol);
//				System.out.flush();
				break;
			case Register16MsSymbol.PDB_ID:
				symbol = new Register16MsSymbol(pdb, reader);
				break;
			case Constant16MsSymbol.PDB_ID:
				symbol = new Constant16MsSymbol(pdb, reader);
				break;
			case UserDefinedType16MsSymbol.PDB_ID:
				symbol = new UserDefinedType16MsSymbol(pdb, reader);
				break;
			case StartSearchMsSymbol.PDB_ID:
				symbol = new StartSearchMsSymbol(pdb, reader);
				break;
			case EndMsSymbol.PDB_ID:
				symbol = new EndMsSymbol(pdb, reader);
				break;
			case SkipMsSymbol.PDB_ID:
				symbol = new SkipMsSymbol(pdb, reader);
				break;
			case CvReservedMsSymbol.PDB_ID:
				symbol = new CvReservedMsSymbol(pdb, reader);
				break;
			case ObjectNameStMsSymbol.PDB_ID:
				symbol = new ObjectNameStMsSymbol(pdb, reader);
				break;
			case EndArgumentsListMsSymbol.PDB_ID:
				symbol = new EndArgumentsListMsSymbol(pdb, reader);
				break;
			case CobolUserDefinedType16MsSymbol.PDB_ID:
				symbol = new CobolUserDefinedType16MsSymbol(pdb, reader);
				break;
			case ManyRegisterVariable16MsSymbol.PDB_ID:
				symbol = new ManyRegisterVariable16MsSymbol(pdb, reader);
				break;
			case ReturnDescriptionMsSymbol.PDB_ID:
				symbol = new ReturnDescriptionMsSymbol(pdb, reader);
				break;
			case EntryThisMsSymbol.PDB_ID:
				symbol = new EntryThisMsSymbol(pdb, reader);
				break;

			// 0x0100 block
			case BasePointerRelative16MsSymbol.PDB_ID:
				symbol = new BasePointerRelative16MsSymbol(pdb, reader);
				break;
			case LocalData16MsSymbol.PDB_ID:
				symbol = new LocalData16MsSymbol(pdb, reader);
				break;
			case GlobalData16MsSymbol.PDB_ID:
				symbol = new GlobalData16MsSymbol(pdb, reader);
				break;
			case Public16MsSymbol.PDB_ID:
				symbol = new Public16MsSymbol(pdb, reader);
				break;
			case LocalProcedureStart16MsSymbol.PDB_ID:
				symbol = new LocalProcedureStart16MsSymbol(pdb, reader);
				break;
			case GlobalProcedureStart16MsSymbol.PDB_ID:
				symbol = new GlobalProcedureStart16MsSymbol(pdb, reader);
				break;
			case Thunk16MsSymbol.PDB_ID:
				symbol = new Thunk16MsSymbol(pdb, reader);
				break;
			case Block16MsSymbol.PDB_ID:
				symbol = new Block16MsSymbol(pdb, reader);
				break;
			case With16MsSymbol.PDB_ID:
				symbol = new With16MsSymbol(pdb, reader);
				break;
			case Label16MsSymbol.PDB_ID:
				symbol = new Label16MsSymbol(pdb, reader);
				break;
			case ChangeExecutionModel16MsSymbol.PDB_ID:
				symbol = new ChangeExecutionModel16MsSymbol(pdb, reader);
				break;
			case VirtualFunctionTable16MsSymbol.PDB_ID:
				symbol = new VirtualFunctionTable16MsSymbol(pdb, reader);
				break;
			case RegisterRelativeAddress16MsSymbol.PDB_ID:
				symbol = new RegisterRelativeAddress16MsSymbol(pdb, reader);
				break;

			// 0x0200 block
			case BasePointerRelative3216MsSymbol.PDB_ID:
				symbol = new BasePointerRelative3216MsSymbol(pdb, reader);
				break;
			case LocalData3216MsSymbol.PDB_ID:
				symbol = new LocalData3216MsSymbol(pdb, reader);
				break;
			case GlobalData3216MsSymbol.PDB_ID:
				symbol = new GlobalData3216MsSymbol(pdb, reader);
				break;
			case Public3216MsSymbol.PDB_ID:
				symbol = new Public3216MsSymbol(pdb, reader);
				break;
			case LocalProcedureStart3216MsSymbol.PDB_ID:
				symbol = new LocalProcedureStart3216MsSymbol(pdb, reader);
				break;
			case GlobalProcedureStart3216MsSymbol.PDB_ID:
				symbol = new GlobalProcedureStart3216MsSymbol(pdb, reader);
				break;
			case Thunk32StMsSymbol.PDB_ID:
				symbol = new Thunk32StMsSymbol(pdb, reader);
				break;
			case Block32StMsSymbol.PDB_ID:
				symbol = new Block32StMsSymbol(pdb, reader);
				break;
			case With32StMsSymbol.PDB_ID:
				symbol = new With32StMsSymbol(pdb, reader);
				break;
			case Label32StMsSymbol.PDB_ID:
				symbol = new Label32StMsSymbol(pdb, reader);
				break;
			case ChangeExecutionModel32MsSymbol.PDB_ID:
				symbol = new ChangeExecutionModel32MsSymbol(pdb, reader);
				break;
			case VirtualFunctionTable3216MsSymbol.PDB_ID:
				symbol = new VirtualFunctionTable3216MsSymbol(pdb, reader);
				break;
			case RegisterRelativeAddress3216MsSymbol.PDB_ID:
				symbol = new RegisterRelativeAddress3216MsSymbol(pdb, reader);
				break;
			case LocalThreadStorage3216MsSymbol.PDB_ID:
				symbol = new LocalThreadStorage3216MsSymbol(pdb, reader);
				break;
			case GlobalThreadStorage3216MsSymbol.PDB_ID:
				symbol = new GlobalThreadStorage3216MsSymbol(pdb, reader);
				break;
			case StaticLinkForMipsExceptionHandlingMsSymbol.PDB_ID:
				symbol = new StaticLinkForMipsExceptionHandlingMsSymbol(pdb, reader);
				break;

			// 0x0300 block
			case LocalProcedureStartMips16MsSymbol.PDB_ID:
				symbol = new LocalProcedureStartMips16MsSymbol(pdb, reader);
				break;
			case GlobalProcedureStartMips16MsSymbol.PDB_ID:
				symbol = new GlobalProcedureStartMips16MsSymbol(pdb, reader);
				break;

			// 0x0400 block
			case ProcedureReferenceStMsSymbol.PDB_ID:
				symbol = new ProcedureReferenceStMsSymbol(pdb, reader);
				break;
			case DataReferenceStMsSymbol.PDB_ID:
				symbol = new DataReferenceStMsSymbol(pdb, reader);
				break;
			case AlignMsSymbol.PDB_ID:
				symbol = new AlignMsSymbol(pdb, reader);
				break;
			case LocalProcedureReferenceStMsSymbol.PDB_ID:
				symbol = new LocalProcedureReferenceStMsSymbol(pdb, reader);
				break;
			case OemDefinedMsSymbol.PDB_ID:
				symbol = new OemDefinedMsSymbol(pdb, reader);
				break;

			// 0x1000 block
			case RegisterStMsSymbol.PDB_ID:
				symbol = new RegisterStMsSymbol(pdb, reader);
				break;
			case ConstantStMsSymbol.PDB_ID:
				symbol = new ConstantStMsSymbol(pdb, reader);
				break;
			case UserDefinedTypeStMsSymbol.PDB_ID:
				symbol = new UserDefinedTypeStMsSymbol(pdb, reader);
				break;
			case CobolUserDefinedTypeStMsSymbol.PDB_ID:
				symbol = new CobolUserDefinedTypeStMsSymbol(pdb, reader);
				break;
			case ManyRegisterVariableStMsSymbol.PDB_ID:
				symbol = new ManyRegisterVariableStMsSymbol(pdb, reader);
				break;
			case BasePointerRelative32StMsSymbol.PDB_ID:
				symbol = new BasePointerRelative32StMsSymbol(pdb, reader);
				break;
			case LocalData32StMsSymbol.PDB_ID:
				symbol = new LocalData32StMsSymbol(pdb, reader);
				break;
			case GlobalData32StMsSymbol.PDB_ID:
				symbol = new GlobalData32StMsSymbol(pdb, reader);
				break;
			case Public32StMsSymbol.PDB_ID:
				symbol = new Public32StMsSymbol(pdb, reader);
				break;
			case LocalProcedureStart32StMsSymbol.PDB_ID:
				symbol = new LocalProcedureStart32StMsSymbol(pdb, reader);
				break;
			case GlobalProcedureStart32StMsSymbol.PDB_ID:
				symbol = new GlobalProcedureStart32StMsSymbol(pdb, reader);
				break;
			case VirtualFunctionTable32MsSymbol.PDB_ID:
				symbol = new VirtualFunctionTable32MsSymbol(pdb, reader);
				break;
			case RegisterRelativeAddress32StMsSymbol.PDB_ID:
				symbol = new RegisterRelativeAddress32StMsSymbol(pdb, reader);
				break;
			case LocalThreadStorage32StMsSymbol.PDB_ID:
				symbol = new LocalThreadStorage32StMsSymbol(pdb, reader);
				break;
			case GlobalThreadStorage32StMsSymbol.PDB_ID:
				symbol = new GlobalThreadStorage32StMsSymbol(pdb, reader);
				break;
			case LocalProcedureStartMipsStMsSymbol.PDB_ID:
				symbol = new LocalProcedureStartMipsStMsSymbol(pdb, reader);
				break;
			case GlobalProcedureStartMipsStMsSymbol.PDB_ID:
				symbol = new GlobalProcedureStartMipsStMsSymbol(pdb, reader);
				break;
			case ExtraFrameAndProcedureInformationMsSymbol.PDB_ID:
				symbol = new ExtraFrameAndProcedureInformationMsSymbol(pdb, reader);
				break;
			case Compile2StMsSymbol.PDB_ID:
				symbol = new Compile2StMsSymbol(pdb, reader);
				break;
			case ManyRegisterVariable2StMsSymbol.PDB_ID:
				symbol = new ManyRegisterVariable2StMsSymbol(pdb, reader);
				break;
			case LocalProcedureStartIa64StMsSymbol.PDB_ID:
				symbol = new LocalProcedureStartIa64StMsSymbol(pdb, reader);
				break;
			case GlobalProcedureStartIa64StMsSymbol.PDB_ID:
				symbol = new GlobalProcedureStartIa64StMsSymbol(pdb, reader);
				break;
			case LocalSlotIndexFieldedLILStMsSymbol.PDB_ID:
				symbol = new LocalSlotIndexFieldedLILStMsSymbol(pdb,
					reader);
				break;
			case ParameterSlotIndexFieldedLILStMsSymbol.PDB_ID:
				symbol = new ParameterSlotIndexFieldedLILStMsSymbol(
					pdb, reader);
				break;
			case AnnotationMsSymbol.PDB_ID:
				symbol = new AnnotationMsSymbol(pdb, reader);
				break;
			case GlobalManagedProcedureStMsSymbol.PDB_ID:
				symbol = new GlobalManagedProcedureStMsSymbol(pdb, reader);
				break;
			case LocalManagedProcedureStMsSymbol.PDB_ID:
				symbol = new LocalManagedProcedureStMsSymbol(pdb, reader);
				break;
			case Reserved1MsSymbol.PDB_ID:
				symbol = new Reserved1MsSymbol(pdb, reader);
				break;
			case Reserved2MsSymbol.PDB_ID:
				symbol = new Reserved2MsSymbol(pdb, reader);
				break;
			case Reserved3MsSymbol.PDB_ID:
				symbol = new Reserved3MsSymbol(pdb, reader);
				break;
			case Reserved4MsSymbol.PDB_ID:
				symbol = new Reserved4MsSymbol(pdb, reader);
				break;
			case LocalManagedDataStMsSymbol.PDB_ID:
				symbol = new LocalManagedDataStMsSymbol(pdb, reader);
				break;
			case GlobalManagedDataStMsSymbol.PDB_ID:
				symbol = new GlobalManagedDataStMsSymbol(pdb, reader);
				break;
			case ManLocOrParamReltoVFPStMsSymbol.PDB_ID:
				symbol =
					new ManLocOrParamReltoVFPStMsSymbol(pdb, reader);
				break;
			case ManagedLocalOrParameterSIRStMsSymbol.PDB_ID:
				symbol = new ManagedLocalOrParameterSIRStMsSymbol(pdb, reader);
				break;
			case ManagedSymbolWithSlotIndexFieldStMsSymbol.PDB_ID:
				symbol = new ManagedSymbolWithSlotIndexFieldStMsSymbol(pdb, reader);
				break;
			case ManagedLocalOrParameterSIMRStMsSymbol.PDB_ID:
				symbol = new ManagedLocalOrParameterSIMRStMsSymbol(pdb, reader);
				break;
			case ManLocOrParamReltoAMPStMsSymbol.PDB_ID:
				symbol = new ManLocOrParamReltoAMPStMsSymbol(pdb,
					reader);
				break;
			case ManagedLocalOrParameterSIMR2StMsSymbol.PDB_ID:
				symbol = new ManagedLocalOrParameterSIMR2StMsSymbol(pdb, reader);
				break;
			case IndexForTypeReferencedByNameFromMetadataMsSymbol.PDB_ID:
				symbol = new IndexForTypeReferencedByNameFromMetadataMsSymbol(pdb, reader);
				break;
			case UsingNamespaceStMsSymbol.PDB_ID:
				symbol = new UsingNamespaceStMsSymbol(pdb, reader);
				break;

			// 0x1100 block
			case ObjectNameMsSymbol.PDB_ID:
				symbol = new ObjectNameMsSymbol(pdb, reader);
				break;
			case Thunk32MsSymbol.PDB_ID:
				symbol = new Thunk32MsSymbol(pdb, reader);
				break;
			case Block32MsSymbol.PDB_ID:
				symbol = new Block32MsSymbol(pdb, reader);
				break;
			case With32MsSymbol.PDB_ID:
				symbol = new With32MsSymbol(pdb, reader);
				break;
			case Label32MsSymbol.PDB_ID:
				symbol = new Label32MsSymbol(pdb, reader);
				break;
			case RegisterMsSymbol.PDB_ID:
				symbol = new RegisterMsSymbol(pdb, reader);
				break;
			case ConstantMsSymbol.PDB_ID:
				symbol = new ConstantMsSymbol(pdb, reader);
				break;
			case UserDefinedTypeMsSymbol.PDB_ID:
				symbol = new UserDefinedTypeMsSymbol(pdb, reader);
				break;
			case CobolUserDefinedTypeMsSymbol.PDB_ID:
				symbol = new CobolUserDefinedTypeMsSymbol(pdb, reader);
				break;
			case ManyRegisterVariableMsSymbol.PDB_ID:
				symbol = new ManyRegisterVariableMsSymbol(pdb, reader);
				break;
			case BasePointerRelative32MsSymbol.PDB_ID:
				symbol = new BasePointerRelative32MsSymbol(pdb, reader);
				break;
			case LocalData32MsSymbol.PDB_ID:
				symbol = new LocalData32MsSymbol(pdb, reader);
				break;
			case GlobalData32MsSymbol.PDB_ID:
				symbol = new GlobalData32MsSymbol(pdb, reader);
				break;
			case Public32MsSymbol.PDB_ID:
				symbol = new Public32MsSymbol(pdb, reader);
				break;
			case LocalProcedureStart32MsSymbol.PDB_ID:
				symbol = new LocalProcedureStart32MsSymbol(pdb, reader);
				break;
			case GlobalProcedureStart32MsSymbol.PDB_ID:
				symbol = new GlobalProcedureStart32MsSymbol(pdb, reader);
				break;
			case RegisterRelativeAddress32MsSymbol.PDB_ID:
				symbol = new RegisterRelativeAddress32MsSymbol(pdb, reader);
				break;
			case LocalThreadStorage32MsSymbol.PDB_ID:
				symbol = new LocalThreadStorage32MsSymbol(pdb, reader);
				break;
			case GlobalThreadStorage32MsSymbol.PDB_ID:
				symbol = new GlobalThreadStorage32MsSymbol(pdb, reader);
				break;
			case LocalProcedureStartMipsMsSymbol.PDB_ID:
				symbol = new LocalProcedureStartMipsMsSymbol(pdb, reader);
				break;
			case GlobalProcedureStartMipsMsSymbol.PDB_ID:
				symbol = new GlobalProcedureStartMipsMsSymbol(pdb, reader);
				break;
			case Compile2MsSymbol.PDB_ID:
				symbol = new Compile2MsSymbol(pdb, reader);
				break;
			case ManyRegisterVariable2MsSymbol.PDB_ID:
				symbol = new ManyRegisterVariable2MsSymbol(pdb, reader);
				break;
			case LocalProcedureStartIa64MsSymbol.PDB_ID:
				symbol = new LocalProcedureStartIa64MsSymbol(pdb, reader);
				break;
			case GlobalProcedureStartIa64MsSymbol.PDB_ID:
				symbol = new GlobalProcedureStartIa64MsSymbol(pdb, reader);
				break;
			case LocalSlotIndexFieldedLILMsSymbol.PDB_ID:
				symbol =
					new LocalSlotIndexFieldedLILMsSymbol(pdb, reader);
				break;
			case ParameterSlotIndexFieldedLILMsSymbol.PDB_ID:
				symbol = new ParameterSlotIndexFieldedLILMsSymbol(pdb,
					reader);
				break;
			case LocalManagedDataMsSymbol.PDB_ID:
				symbol = new LocalManagedDataMsSymbol(pdb, reader);
				break;
			case GlobalManagedDataMsSymbol.PDB_ID:
				symbol = new GlobalManagedDataMsSymbol(pdb, reader);
				break;
			case ManLocOrParamReltoVFPMsSymbol.PDB_ID:
				symbol =
					new ManLocOrParamReltoVFPMsSymbol(pdb, reader);
				break;
			case ManagedLocalOrParameterSIRMsSymbol.PDB_ID:
				symbol = new ManagedLocalOrParameterSIRMsSymbol(pdb, reader);
				break;
			case ManagedSymbolWithSlotIndexFieldMsSymbol.PDB_ID:
				symbol = new ManagedSymbolWithSlotIndexFieldMsSymbol(pdb, reader);
				break;
			case ManagedLocalOrParameterSIMRMsSymbol.PDB_ID:
				symbol = new ManagedLocalOrParameterSIMRMsSymbol(pdb, reader);
				break;
			case ManLocOrParamReltoAMPMsSymbol.PDB_ID:
				symbol =
					new ManLocOrParamReltoAMPMsSymbol(pdb, reader);
				break;
			case ManagedLocalOrParameterSIMR2MsSymbol.PDB_ID:
				symbol = new ManagedLocalOrParameterSIMR2MsSymbol(pdb, reader);
				break;
			case UsingNamespaceMsSymbol.PDB_ID:
				symbol = new UsingNamespaceMsSymbol(pdb, reader);
				break;
			case ProcedureReferenceMsSymbol.PDB_ID:
				symbol = new ProcedureReferenceMsSymbol(pdb, reader);
				break;
			case DataReferenceMsSymbol.PDB_ID:
				symbol = new DataReferenceMsSymbol(pdb, reader);
				break;
			case LocalProcedureReferenceMsSymbol.PDB_ID:
				symbol = new LocalProcedureReferenceMsSymbol(pdb, reader);
				break;
			case AnnotationReferenceMsSymbol.PDB_ID:
				symbol = new AnnotationReferenceMsSymbol(pdb, reader);
				break;
			case TokenReferenceToManagedProcedureMsSymbol.PDB_ID:
				symbol = new TokenReferenceToManagedProcedureMsSymbol(pdb, reader);
				break;
			case GlobalManagedProcedureMsSymbol.PDB_ID:
				symbol = new GlobalManagedProcedureMsSymbol(pdb, reader);
				break;
			case LocalManagedProcedureMsSymbol.PDB_ID:
				symbol = new LocalManagedProcedureMsSymbol(pdb, reader);
				break;
			case TrampolineMsSymbol.PDB_ID:
				symbol = new TrampolineMsSymbol(pdb, reader);
				break;
			case ManagedConstantMsSymbol.PDB_ID:
				symbol = new ManagedConstantMsSymbol(pdb, reader);
				break;
			case AttribLocOrParamReltoVFPMsSymbol.PDB_ID:
				symbol = new AttribLocOrParamReltoVFPMsSymbol(pdb,
					reader);
				break;
			case AttributedLocalOrParameterSIRMsSymbol.PDB_ID:
				symbol = new AttributedLocalOrParameterSIRMsSymbol(pdb, reader);
				break;
			case AttribLocOrParamReltoAMPMsSymbol.PDB_ID:
				symbol = new AttribLocOrParamReltoAMPMsSymbol(pdb,
					reader);
				break;
			case AttributedLocalOrParameterSIMRMsSymbol.PDB_ID:
				symbol = new AttributedLocalOrParameterSIMRMsSymbol(pdb, reader);
				break;
			case SeparatedCodeFromCompilerSupportMsSymbol.PDB_ID:
				symbol = new SeparatedCodeFromCompilerSupportMsSymbol(pdb, reader);
				break;
			case LocalSymbolInOptimizedCode2005MsSymbol.PDB_ID:
				symbol = new LocalSymbolInOptimizedCode2005MsSymbol(pdb, reader);
				break;
			case DefinedSingleAddressRange2005MsSymbol.PDB_ID:
				symbol = new DefinedSingleAddressRange2005MsSymbol(pdb, reader);
				break;
			case DefinedMultipleAddressRanges2005MsSymbol.PDB_ID:
				symbol = new DefinedMultipleAddressRanges2005MsSymbol(pdb, reader);
				break;
			case PeCoffSectionMsSymbol.PDB_ID:
				symbol = new PeCoffSectionMsSymbol(pdb, reader);
				break;
			case PeCoffGroupMsSymbol.PDB_ID:
				symbol = new PeCoffGroupMsSymbol(pdb, reader);
				break;
			case ExportMsSymbol.PDB_ID:
				symbol = new ExportMsSymbol(pdb, reader);
				break;
			case IndirectCallSiteInfoMsSymbol.PDB_ID:
				symbol = new IndirectCallSiteInfoMsSymbol(pdb, reader);
				break;
			case FrameSecurityCookieMsSymbol.PDB_ID:
				symbol = new FrameSecurityCookieMsSymbol(pdb, reader);
				break;
			case DiscardedByLinkMsSymbol.PDB_ID:
				symbol = new DiscardedByLinkMsSymbol(pdb, reader);
				break;
			case Compile3MsSymbol.PDB_ID:
				symbol = new Compile3MsSymbol(pdb, reader);
				break;
			case EnvironmentBlockMsSymbol.PDB_ID:
				symbol = new EnvironmentBlockMsSymbol(pdb, reader);
				break;
			case LocalSymbolInOptimizedCodeMsSymbol.PDB_ID:
				symbol = new LocalSymbolInOptimizedCodeMsSymbol(pdb, reader);
				break;
			case DefinedSingleAddressRangeMsSymbol.PDB_ID:
				symbol = new DefinedSingleAddressRangeMsSymbol(pdb, reader);
				break;
			case SubfieldDARMsSymbol.PDB_ID:
				symbol = new SubfieldDARMsSymbol(pdb, reader);
				break;
			case EnregisteredSymbolDARMsSymbol.PDB_ID:
				symbol = new EnregisteredSymbolDARMsSymbol(pdb, reader);
				break;
			case FramePointerRelativeDARMsSymbol.PDB_ID:
				symbol = new FramePointerRelativeDARMsSymbol(pdb, reader);
				break;
			case EnregisteredFieldOfSymbolDARMsSymbol.PDB_ID:
				symbol =
					new EnregisteredFieldOfSymbolDARMsSymbol(pdb, reader);
				break;
			case FramePointerRelativeFullScopeDARMsSymbol.PDB_ID:
				symbol = new FramePointerRelativeFullScopeDARMsSymbol(pdb,
					reader);
				break;
			case EnregisteredSymbolRelativeDARMsSymbol.PDB_ID:
				symbol =
					new EnregisteredSymbolRelativeDARMsSymbol(pdb, reader);
				break;
			case LocalProcedure32IdMsSymbol.PDB_ID:
				symbol = new LocalProcedure32IdMsSymbol(pdb, reader);
				break;
			case GlobalProcedure32IdMsSymbol.PDB_ID:
				symbol = new GlobalProcedure32IdMsSymbol(pdb, reader);
				break;
			case LocalProcedureMipsIdMsSymbol.PDB_ID:
				symbol = new LocalProcedureMipsIdMsSymbol(pdb, reader);
				break;
			case GlobalProcedureMipsIdMsSymbol.PDB_ID:
				symbol = new GlobalProcedureMipsIdMsSymbol(pdb, reader);
				break;
			case LocalProcedureIa64IdMsSymbol.PDB_ID:
				symbol = new LocalProcedureIa64IdMsSymbol(pdb, reader);
				break;
			case GlobalProcedureIa64IdMsSymbol.PDB_ID:
				symbol = new GlobalProcedureIa64IdMsSymbol(pdb, reader);
				break;
			case BuildInformationMsSymbol.PDB_ID:
				symbol = new BuildInformationMsSymbol(pdb, reader);
				break;
			case InlinedFunctionCallsiteMsSymbol.PDB_ID:
				symbol = new InlinedFunctionCallsiteMsSymbol(pdb, reader);
				break;
			case InlinedFunctionEndMsSymbol.PDB_ID:
				symbol = new InlinedFunctionEndMsSymbol(pdb, reader);
				break;
			case ProcedureIdEndMsSymbol.PDB_ID:
				symbol = new ProcedureIdEndMsSymbol(pdb, reader);
				break;
			case HighLevelShaderLanguageRegDimDARMsSymbol.PDB_ID:
				symbol = new HighLevelShaderLanguageRegDimDARMsSymbol(pdb, reader);
				break;
			case GlobalDataHLSLMsSymbol.PDB_ID:
				symbol = new GlobalDataHLSLMsSymbol(pdb, reader);
				break;
			case LocalDataHLSLMsSymbol.PDB_ID:
				symbol = new LocalDataHLSLMsSymbol(pdb, reader);
				break;
			case FileStaticMsSymbol.PDB_ID:
				symbol = new FileStaticMsSymbol(pdb, reader);
				break;
			case LocalDeferredProcedureCallGroupSharedMsSymbol.PDB_ID:
				symbol = new LocalDeferredProcedureCallGroupSharedMsSymbol(pdb, reader);
				break;
			case LocalProcedureStart32DeferredProcedureCallMsSymbol.PDB_ID:
				symbol = new LocalProcedureStart32DeferredProcedureCallMsSymbol(pdb, reader);
				break;
			case LocalProcedure32DeferredProcedureCallIdMsSymbol.PDB_ID:
				symbol = new LocalProcedure32DeferredProcedureCallIdMsSymbol(pdb, reader);
				break;
			case DeferredProcedureCallPointerTagRegDimDARMsSymbol.PDB_ID:
				symbol =
					new DeferredProcedureCallPointerTagRegDimDARMsSymbol(pdb, reader);
				break;
			case DeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol.PDB_ID:
				symbol = new DeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol(pdb, reader);
				break;
			case ArmSwitchTableMsSymbol.PDB_ID:
				symbol = new ArmSwitchTableMsSymbol(pdb, reader);
				break;
			case CalleesMsSymbol.PDB_ID:
				symbol = new CalleesMsSymbol(pdb, reader);
				break;
			case CallersMsSymbol.PDB_ID:
				symbol = new CallersMsSymbol(pdb, reader);
				break;
			case ProfileGuidedOptimizationDataMsSymbol.PDB_ID:
				symbol = new ProfileGuidedOptimizationDataMsSymbol(pdb, reader);
				break;
			case InlinedFunctionCallsiteExtendedMsSymbol.PDB_ID:
				symbol = new InlinedFunctionCallsiteExtendedMsSymbol(pdb, reader);
				break;
			case HeapAllocationSiteMsSymbol.PDB_ID:
				symbol = new HeapAllocationSiteMsSymbol(pdb, reader);
				break;
			case ModuleTypeReferenceMsSymbol.PDB_ID:
				symbol = new ModuleTypeReferenceMsSymbol(pdb, reader);
				break;
			case MiniPdbReferenceMsSymbol.PDB_ID:
				symbol = new MiniPdbReferenceMsSymbol(pdb, reader);
				break;
			case MapToMiniPdbMsSymbol.PDB_ID:
				symbol = new MapToMiniPdbMsSymbol(pdb, reader);
				break;
			case GlobalDataHLSL32MsSymbol.PDB_ID:
				symbol = new GlobalDataHLSL32MsSymbol(pdb, reader);
				break;
			case LocalDataHLSL32MsSymbol.PDB_ID:
				symbol = new LocalDataHLSL32MsSymbol(pdb, reader);
				break;
			case GlobalDataHLSL32ExtMsSymbol.PDB_ID:
				symbol = new GlobalDataHLSL32ExtMsSymbol(pdb, reader);
				break;
			case LocalDataHLSL32ExtMsSymbol.PDB_ID:
				symbol = new LocalDataHLSL32ExtMsSymbol(pdb, reader);
				break;

			// These should never happen (unless we missed something
			// or MSFT has added new in a version we do not handle.
			// We have recently seen 1167 and 1168, which implies that 1166 must exist.
			case UnknownX1166MsSymbol.PDB_ID:
				symbol = new UnknownX1166MsSymbol(pdb, reader);
				break;
			case UnknownX1167MsSymbol.PDB_ID:
				symbol = new UnknownX1167MsSymbol(pdb, reader);
				break;
			case UnknownX1168MsSymbol.PDB_ID:
				symbol = new UnknownX1168MsSymbol(pdb, reader);
				break;
			default:
				//System.out.println(String.format("Unknown symbolType: %04x", symbolType));
				//System.out.println(reader.dump(0x200));
				//assert false;
				symbol = new UnknownMsSymbol(pdb, reader, symbolTypeId);
				break;
		}

		return symbol;
	}

}
