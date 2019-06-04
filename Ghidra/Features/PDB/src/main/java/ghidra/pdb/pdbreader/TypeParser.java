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

import java.util.*;

import org.apache.commons.lang3.Validate;

import ghidra.pdb.*;
import ghidra.pdb.pdbreader.type.*;
import ghidra.util.exception.CancelledException;

/**
 * Parser for detecting the parsing the appropriate Data\Item structures ({@link AbstractMsType})
 *  in the PDB.
 */
public class TypeParser {

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected AbstractPdb pdb;

	/**
	 * This data is used as we develop this capability, and we could actively use it during
	 *  normal operations to give feedback towards this continued development.
	 * <P>
	 * The list indicates which Data Types ({@link AbstractMsType}) have been seen in real data,
	 *  giving us some confidence as to whether we have parsed them OK or not.  We can set a break
	 *  point in the method containing the switch statement to trigger whenever we find a
	 *  symbol type not in this list.
	 */
	private static Set<Integer> dataTypesSeen = new HashSet<>();
	private Set<Integer> newDataTypesSeen = new HashSet<>();
	static {
		dataTypesSeen.add(0x0001);
		dataTypesSeen.add(0x0002);
		dataTypesSeen.add(0x0003);
		dataTypesSeen.add(0x0004);
		dataTypesSeen.add(0x0005);
		dataTypesSeen.add(0x0006);
		dataTypesSeen.add(0x0007);
		dataTypesSeen.add(0x0008);
		dataTypesSeen.add(0x0009);
		dataTypesSeen.add(0x000a);
//		dataTypesSeen.add(0x000b);
//		dataTypesSeen.add(0x000c);
//		dataTypesSeen.add(0x000d);
//		dataTypesSeen.add(0x000e);
//		dataTypesSeen.add(0x000f);
//		dataTypesSeen.add(0x0010);
//		dataTypesSeen.add(0x0011);
//		dataTypesSeen.add(0x0012);
//		dataTypesSeen.add(0x0013);
//		dataTypesSeen.add(0x0014);
//		dataTypesSeen.add(0x0015);
//		dataTypesSeen.add(0x0016);

//		dataTypesSeen.add(0x0200);
		dataTypesSeen.add(0x0201);
//		dataTypesSeen.add(0x0202);
//		dataTypesSeen.add(0x0203);
		dataTypesSeen.add(0x0204);
//		dataTypesSeen.add(0x0205);
		dataTypesSeen.add(0x0206);
		dataTypesSeen.add(0x0207);
//		dataTypesSeen.add(0x0208);
//		dataTypesSeen.add(0x0209);
//		dataTypesSeen.add(0x020a);
//		dataTypesSeen.add(0x020b);
//		dataTypesSeen.add(0x020c);

		dataTypesSeen.add(0x0400);
//		dataTypesSeen.add(0x0401);
//		dataTypesSeen.add(0x0402);
		dataTypesSeen.add(0x0403);
//		dataTypesSeen.add(0x0404);
//		dataTypesSeen.add(0x0405);
		dataTypesSeen.add(0x0406);
		dataTypesSeen.add(0x0407);
		dataTypesSeen.add(0x0408);
		dataTypesSeen.add(0x0409);
		dataTypesSeen.add(0x040a);
//		dataTypesSeen.add(0x040b);
		dataTypesSeen.add(0x040c);
//		dataTypesSeen.add(0x040d);

		dataTypesSeen.add(0x1001);
		dataTypesSeen.add(0x1002);
		dataTypesSeen.add(0x1003);
		dataTypesSeen.add(0x1004);
		dataTypesSeen.add(0x1005);
		dataTypesSeen.add(0x1006);
		dataTypesSeen.add(0x1007);
		dataTypesSeen.add(0x1008);
		dataTypesSeen.add(0x1009);
//		dataTypesSeen.add(0x100a);
//		dataTypesSeen.add(0x100b);
//		dataTypesSeen.add(0x100c);
//		dataTypesSeen.add(0x100d);
//		dataTypesSeen.add(0x100e);
//		dataTypesSeen.add(0x100f);
//		dataTypesSeen.add(0x1010);
//		dataTypesSeen.add(0x1011);

		dataTypesSeen.add(0x1201);
//		dataTypesSeen.add(0x1202);
		dataTypesSeen.add(0x1203);
//		dataTypesSeen.add(0x1204);
		dataTypesSeen.add(0x1205); //Bit-fields
		dataTypesSeen.add(0x1206);
//		dataTypesSeen.add(0x1207);
//		dataTypesSeen.add(0x1209);
//		dataTypesSeen.add(0x1209);
//		dataTypesSeen.add(0x120a);

		dataTypesSeen.add(0x1400);
		dataTypesSeen.add(0x1401);
		dataTypesSeen.add(0x1402);
//		dataTypesSeen.add(0x1403);
		dataTypesSeen.add(0x1404);
		dataTypesSeen.add(0x1405);
		dataTypesSeen.add(0x1406);
		dataTypesSeen.add(0x1407);
		dataTypesSeen.add(0x1408);
		dataTypesSeen.add(0x1409);
//		dataTypesSeen.add(0x140a);
		dataTypesSeen.add(0x140b);
//		dataTypesSeen.add(0x140c);
//		dataTypesSeen.add(0x140d);
//		dataTypesSeen.add(0x140e);
//		dataTypesSeen.add(0x140f);

//		dataTypesSeen.add(0x1501);
		dataTypesSeen.add(0x1502);
		dataTypesSeen.add(0x1503);
		dataTypesSeen.add(0x1504);
		dataTypesSeen.add(0x1505); //Structures
		dataTypesSeen.add(0x1506);
		dataTypesSeen.add(0x1507);
//		dataTypesSeen.add(0x1508);
//		dataTypesSeen.add(0x1509);
//		dataTypesSeen.add(0x150a);
//		dataTypesSeen.add(0x150b);
//		dataTypesSeen.add(0x150c);
		dataTypesSeen.add(0x150d);
		dataTypesSeen.add(0x150e);
		dataTypesSeen.add(0x150f);
		dataTypesSeen.add(0x1510);
		dataTypesSeen.add(0x1511);
//		dataTypesSeen.add(0x1512);
//		dataTypesSeen.add(0x1513);
//		dataTypesSeen.add(0x1514);
//		dataTypesSeen.add(0x1515);
//		dataTypesSeen.add(0x1516);
//		dataTypesSeen.add(0x1517);
//		dataTypesSeen.add(0x1518);
//		dataTypesSeen.add(0x1519);
//		dataTypesSeen.add(0x151a);
//		dataTypesSeen.add(0x151b);
//		dataTypesSeen.add(0x151c);
		dataTypesSeen.add(0x151d);

		dataTypesSeen.add(0x1601);
		dataTypesSeen.add(0x1602);
		dataTypesSeen.add(0x1603);
		dataTypesSeen.add(0x1604);
		dataTypesSeen.add(0x1605);
		dataTypesSeen.add(0x1606);
		dataTypesSeen.add(0x1607);
	}

	protected CategoryIndex.Category category;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns the Symbols to be parsed.
	 */
	public TypeParser(AbstractPdb pdb) {
		Validate.notNull(pdb, "pdb cannot be null)");
		this.pdb = pdb;
	}

	/**
	 * Returns a list of Symbol IDs that we have not seen in real data while testing.
	 * @return {@link String} of pretty output message.
	 */
	public String getNewDataTypesLog() {
		StringBuilder builder = new StringBuilder();
		DelimiterState ds = new DelimiterState("New Symbol IDs Seen: ", ",");
		/**
		 *  We are creating the sorted set now, as we are willing to incur the cost of a sorted
		 *  set now, but do not want to incur too much debug cost for adding to the
		 *  {@link newDataTypesSeen} when not doing debug.
		 */
		Set<Integer> sortedSet = new TreeSet<>(newDataTypesSeen);
		for (Integer val : sortedSet) {
			builder.append(ds.out(true, String.format("0X%04X", val)));
		}
		return builder.toString();
	}

	/**
	 * Deserializes an {@link AbstractMsType} from the {@link PdbByteReader} and returns it.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @return {@link AbstractMsType} parsed.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	public AbstractMsType parse(PdbByteReader reader) throws PdbException, CancelledException {
		int dataTypeId = reader.parseUnsignedShortVal();
		AbstractMsType type;
		try {
			type = parseRecord(dataTypeId, reader);
		}
		catch (PdbException e) {
			type = new BadMsType(pdb, dataTypeId);
		}
		return type;
	}

	/**
	 * Deserializes an {@link AbstractMsType} from the {@link PdbByteReader} and returns it.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @return {@link AbstractMsType} parsed.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	private AbstractMsType parseRecord(int dataTypeId, PdbByteReader reader)
			throws PdbException, CancelledException {
		//Debugging and research investigation
		//System.out.println(reader.dump());
		// Leaving commented-out code here for continued research/development
//		if (dataTypeId == 0x204) {
//			if ((length >= 4) && (selectedBytes[1] != 0x04) && !((selectedBytes[0] == 0x00) ||
//				(selectedBytes[0] == 0x06) || (selectedBytes[0] == 0x0c))) {
//				dump(bytes);
//			}
//		}

		if (!dataTypesSeen.contains(dataTypeId)) {
			newDataTypesSeen.add(dataTypeId);
//			//System.out.println(String.format("Data Type not seen before: %04x", dataTypeId));
//			// DO NOT REMOVE
//			// Set break point on instruction below to trigger on any data types that we
//			//  have not seen in real data.  Then step through the parsing for these new
//			//  data types to confirm that our parsing and the real data agree.  Also, comment
//			//  in the line above to show the ID for this type whenever desired.
//			int a = 1;
//			a = a + 1;
		}

		AbstractMsType type = null;
		switch (dataTypeId) {
			// 0x0000 block
			case Modifier16MsType.PDB_ID:
				type = new Modifier16MsType(pdb, reader);
				//System.out.println(type.toString());
				//System.out.flush();
				break;
			case Pointer16MsType.PDB_ID:
				type = new Pointer16MsType(pdb, reader);
				break;
			case Array16MsType.PDB_ID:
				type = new Array16MsType(pdb, reader);
				break;
			case Class16MsType.PDB_ID:
				type = new Class16MsType(pdb, reader);
				break;
			case Structure16MsType.PDB_ID:
				type = new Structure16MsType(pdb, reader);
				break;
			case Union16MsType.PDB_ID:
				type = new Union16MsType(pdb, reader);
				break;
			case Enum16MsType.PDB_ID:
				type = new Enum16MsType(pdb, reader);
				break;
			case Procedure16MsType.PDB_ID:
				type = new Procedure16MsType(pdb, reader);
				break;
			case MemberFunction16MsType.PDB_ID:
				type = new MemberFunction16MsType(pdb, reader);
				break;
			case VtShapeMsType.PDB_ID:
				type = new VtShapeMsType(pdb, reader);
				break;
			case Cobol016MsType.PDB_ID:
				type = new Cobol016MsType(pdb, reader);
				break;
			case Cobol1MsType.PDB_ID:
				type = new Cobol1MsType(pdb, reader);
				break;
			case BasicArray16MsType.PDB_ID:
				type = new BasicArray16MsType(pdb, reader);
				break;
			case LabelMsType.PDB_ID:
				type = new LabelMsType(pdb, reader);
				break;
			case NullMsType.PDB_ID:
				type = new NullMsType(pdb, reader);
				break;
			case NotTranMsType.PDB_ID:
				type = new NotTranMsType(pdb, reader);
				break;
			case DimensionedArray16MsType.PDB_ID:
				type = new DimensionedArray16MsType(pdb, reader);
				break;
			case VirtualFunctionTablePath16MsType.PDB_ID:
				type = new VirtualFunctionTablePath16MsType(pdb, reader);
				break;
			case PrecompiledType16MsType.PDB_ID:
				type = new PrecompiledType16MsType(pdb, reader);
				break;
			case EndPrecompiledTypeMsType.PDB_ID:
				type = new EndPrecompiledTypeMsType(pdb, reader);
				break;
			case OemDefinableString16MsType.PDB_ID:
				type = new OemDefinableString16MsType(pdb, reader);
				break;
			case TypeServerStMsType.PDB_ID:
				type = new TypeServerStMsType(pdb, reader);
				break;

			// 0x0200 block
			case Skip16MsType.PDB_ID:
				type = new Skip16MsType(pdb, reader);
				break;
			case ArgumentsList16MsType.PDB_ID:
				type = new ArgumentsList16MsType(pdb, reader);
				break;
			case DefaultArguments16MsType.PDB_ID:
				type = new DefaultArguments16MsType(pdb, reader);
				break;
			case ListMsType.PDB_ID:
				type = new ListMsType(pdb, reader);
				break;
			case FieldList16MsType.PDB_ID:
				type = new FieldList16MsType(pdb, reader);
				break;
			case DerivedClassList16MsType.PDB_ID:
				type = new DerivedClassList16MsType(pdb, reader);
				break;
			case Bitfield16MsType.PDB_ID:
				type = new Bitfield16MsType(pdb, reader);
				break;
			case MethodList16MsType.PDB_ID:
				type = new MethodList16MsType(pdb, reader);
				break;
			case DimensionedArrayConstBoundsUpper16MsType.PDB_ID:
				type = new DimensionedArrayConstBoundsUpper16MsType(pdb, reader);
				break;
			case DimensionedArrayConstBoundsLowerUpper16MsType.PDB_ID:
				type = new DimensionedArrayConstBoundsLowerUpper16MsType(pdb, reader);
				break;
			case DimensionedArrayVarBoundsUpper16MsType.PDB_ID:
				type = new DimensionedArrayVarBoundsUpper16MsType(pdb, reader);
				break;
			case DimensionedArrayVarBoundsLowerUpper16MsType.PDB_ID:
				type = new DimensionedArrayVarBoundsLowerUpper16MsType(pdb, reader);
				break;
			case ReferencedSymbolMsType.PDB_ID:
				type = new ReferencedSymbolMsType(pdb, reader);
				break;

			// 0x400 block
			case BaseClass16MsType.PDB_ID:
				type = new BaseClass16MsType(pdb, reader);
				break;
			case VirtualBaseClass16MsType.PDB_ID:
				type = new VirtualBaseClass16MsType(pdb, reader);
				break;
			case IndirectVirtualBaseClass16MsType.PDB_ID:
				type = new IndirectVirtualBaseClass16MsType(pdb, reader);
				break;
			case EnumerateStMsType.PDB_ID:
				type = new EnumerateStMsType(pdb, reader);
				break;
			case FriendFunction16MsType.PDB_ID:
				type = new FriendFunction16MsType(pdb, reader);
				break;
			case Index16MsType.PDB_ID:
				type = new Index16MsType(pdb, reader);
				break;
			case Member16MsType.PDB_ID:
				type = new Member16MsType(pdb, reader);
				break;
			case StaticMember16MsType.PDB_ID:
				type = new StaticMember16MsType(pdb, reader);
				break;
			case OverloadedMethod16MsType.PDB_ID:
				type = new OverloadedMethod16MsType(pdb, reader);
				break;
			case NestedType16MsType.PDB_ID:
				type = new NestedType16MsType(pdb, reader);
				break;
			case VirtualFunctionTablePointer16MsType.PDB_ID:
				type = new VirtualFunctionTablePointer16MsType(pdb, reader);
				break;
			case FriendClass16MsType.PDB_ID:
				type = new FriendClass16MsType(pdb, reader);
				break;
			case OneMethod16MsType.PDB_ID:
				type = new OneMethod16MsType(pdb, reader);
				break;
			case VirtualFunctionTablePointerWithOffset16MsType.PDB_ID:
				type = new VirtualFunctionTablePointerWithOffset16MsType(pdb, reader);
				break;

			// 0x1000 block
			case ModifierMsType.PDB_ID:
				type = new ModifierMsType(pdb, reader);
				break;
			case PointerMsType.PDB_ID:
				type = new PointerMsType(pdb, reader);
				break;
			case ArrayStMsType.PDB_ID:
				type = new ArrayStMsType(pdb, reader);
				break;
			case ClassStMsType.PDB_ID:
				type = new ClassStMsType(pdb, reader);
				break;
			case StructureStMsType.PDB_ID:
				type = new StructureStMsType(pdb, reader);
				break;
			case UnionStMsType.PDB_ID:
				type = new UnionStMsType(pdb, reader);
				break;
			case EnumStMsType.PDB_ID:
				type = new EnumStMsType(pdb, reader);
				break;
			case ProcedureMsType.PDB_ID:
				type = new ProcedureMsType(pdb, reader);
				break;
			case MemberFunctionMsType.PDB_ID:
				type = new MemberFunctionMsType(pdb, reader);
				break;
			case Cobol0MsType.PDB_ID:
				type = new Cobol0MsType(pdb, reader);
				break;
			case BasicArrayMsType.PDB_ID:
				type = new BasicArrayMsType(pdb, reader);
				break;
			case DimensionedArrayStMsType.PDB_ID:
				type = new DimensionedArrayStMsType(pdb, reader);
				break;
			case VirtualFunctionTablePathMsType.PDB_ID:
				type = new VirtualFunctionTablePathMsType(pdb, reader);
				break;
			case PrecompiledTypeStMsType.PDB_ID:
				type = new PrecompiledTypeStMsType(pdb, reader);
				break;
			case OemDefinableStringMsType.PDB_ID:
				type = new OemDefinableStringMsType(pdb, reader);
				break;
			case AliasStMsType.PDB_ID:
				type = new AliasStMsType(pdb, reader);
				break;
			case OemDefinableString2MsType.PDB_ID:
				type = new OemDefinableString2MsType(pdb, reader);
				break;

			// 0x1200 block
			case SkipMsType.PDB_ID:
				type = new SkipMsType(pdb, reader);
				break;
			case ArgumentsListMsType.PDB_ID:
				type = new ArgumentsListMsType(pdb, reader);
				break;
			case DefaultArgumentsStMsType.PDB_ID:
				type = new DefaultArgumentsStMsType(pdb, reader);
				break;
			case FieldListMsType.PDB_ID:
				type = new FieldListMsType(pdb, reader);
				break;
			case DerivedClassListMsType.PDB_ID:
				type = new DerivedClassListMsType(pdb, reader);
				break;
			case BitfieldMsType.PDB_ID:
				type = new BitfieldMsType(pdb, reader);
				break;
			case MethodListMsType.PDB_ID:
				type = new MethodListMsType(pdb, reader);
				break;
			case DimensionedArrayConstBoundsUpperMsType.PDB_ID:
				type = new DimensionedArrayConstBoundsUpperMsType(pdb, reader);
				break;
			case DimensionedArrayConstBoundsLowerUpperMsType.PDB_ID:
				type = new DimensionedArrayConstBoundsLowerUpperMsType(pdb, reader);
				break;
			case DimensionedArrayVarBoundsUpperMsType.PDB_ID:
				type = new DimensionedArrayVarBoundsUpperMsType(pdb, reader);
				break;
			case DimensionedArrayVarBoundsLowerUpperMsType.PDB_ID:
				type = new DimensionedArrayVarBoundsLowerUpperMsType(pdb, reader);
				break;

			// 0x1400 block
			case BaseClassMsType.PDB_ID:
				type = new BaseClassMsType(pdb, reader);
				break;
			case VirtualBaseClassMsType.PDB_ID:
				type = new VirtualBaseClassMsType(pdb, reader);
				break;
			case IndirectVirtualBaseClassMsType.PDB_ID:
				type = new IndirectVirtualBaseClassMsType(pdb, reader);
				break;
			case FriendFunctionStMsType.PDB_ID:
				type = new FriendFunctionStMsType(pdb, reader);
				break;
			case IndexMsType.PDB_ID:
				type = new IndexMsType(pdb, reader);
				break;
			case MemberStMsType.PDB_ID:
				type = new MemberStMsType(pdb, reader);
				break;
			case StaticMemberStMsType.PDB_ID:
				type = new StaticMemberStMsType(pdb, reader);
				break;
			case OverloadedMethodStMsType.PDB_ID:
				type = new OverloadedMethodStMsType(pdb, reader);
				break;
			case NestedTypeStMsType.PDB_ID:
				type = new NestedTypeStMsType(pdb, reader);
				break;
			case VirtualFunctionTablePointerMsType.PDB_ID:
				type = new VirtualFunctionTablePointerMsType(pdb, reader);
				break;
			case FriendClassMsType.PDB_ID:
				type = new FriendClassMsType(pdb, reader);
				break;
			case OneMethodStMsType.PDB_ID:
				type = new OneMethodStMsType(pdb, reader);
				break;
			case VirtualFunctionTablePointerWithOffsetMsType.PDB_ID:
				type = new VirtualFunctionTablePointerWithOffsetMsType(pdb, reader);
				break;
			case NestedTypeExtStMsType.PDB_ID:
				type = new NestedTypeExtStMsType(pdb, reader);
				break;
			case MemberModifyStMsType.PDB_ID:
				type = new MemberModifyStMsType(pdb, reader);
				break;
			case ManagedStMsType.PDB_ID:
				type = new ManagedStMsType(pdb, reader);
				break;

			// 0x1500 block 
			case TypeServerMsType.PDB_ID:
				type = new TypeServerMsType(pdb, reader);
				break;
			case EnumerateMsType.PDB_ID:
				type = new EnumerateMsType(pdb, reader);
				break;
			case ArrayMsType.PDB_ID:
				type = new ArrayMsType(pdb, reader);
				break;
			case ClassMsType.PDB_ID:
				type = new ClassMsType(pdb, reader);
				break;
			case StructureMsType.PDB_ID:
				type = new StructureMsType(pdb, reader);
				break;
			case UnionMsType.PDB_ID:
				type = new UnionMsType(pdb, reader);
				break;
			case EnumMsType.PDB_ID:
				type = new EnumMsType(pdb, reader);
				break;
			case DimensionedArrayMsType.PDB_ID:
				type = new DimensionedArrayMsType(pdb, reader);
				break;
			case PrecompiledTypeMsType.PDB_ID:
				type = new PrecompiledTypeMsType(pdb, reader);
				break;
			case AliasMsType.PDB_ID:
				type = new AliasMsType(pdb, reader);
				break;
			case DefaultArgumentsMsType.PDB_ID:
				type = new DefaultArgumentsMsType(pdb, reader);
				break;
			case FriendFunctionMsType.PDB_ID:
				type = new FriendFunctionMsType(pdb, reader);
				break;
			case MemberMsType.PDB_ID:
				type = new MemberMsType(pdb, reader);
				break;
			case StaticMemberMsType.PDB_ID:
				type = new StaticMemberMsType(pdb, reader);
				break;
			case OverloadedMethodMsType.PDB_ID:
				type = new OverloadedMethodMsType(pdb, reader);
				break;
			case NestedTypeMsType.PDB_ID:
				type = new NestedTypeMsType(pdb, reader);
				break;
			case OneMethodMsType.PDB_ID:
				type = new OneMethodMsType(pdb, reader);
				break;
			case NestedTypeExtMsType.PDB_ID:
				type = new NestedTypeExtMsType(pdb, reader);
				break;
			case MemberModifyMsType.PDB_ID:
				type = new MemberModifyMsType(pdb, reader);
				break;
			case ManagedMsType.PDB_ID:
				type = new ManagedMsType(pdb, reader);
				break;
			case TypeServer2MsType.PDB_ID:
				type = new TypeServer2MsType(pdb, reader);
				break;
			case StridedArrayMsType.PDB_ID:
				type = new StridedArrayMsType(pdb, reader);
				break;
			case HighLevelShaderLanguageMsType.PDB_ID:
				type = new HighLevelShaderLanguageMsType(pdb, reader);
				break;
			case ModifierExMsType.PDB_ID:
				type = new ModifierExMsType(pdb, reader);
				break;
			case InterfaceMsType.PDB_ID:
				type = new InterfaceMsType(pdb, reader);
				break;
			case BaseInterfaceMsType.PDB_ID:
				type = new BaseInterfaceMsType(pdb, reader);
				break;
			case VectorMsType.PDB_ID:
				type = new VectorMsType(pdb, reader);
				break;
			case MatrixMsType.PDB_ID:
				type = new MatrixMsType(pdb, reader);
				break;
			case VirtualFunctionTableMsType.PDB_ID:
				type = new VirtualFunctionTableMsType(pdb, reader);
				break;

			// 0x1600 block 
			case FunctionIdMsType.PDB_ID:
				type = new FunctionIdMsType(pdb, reader);
				break;
			case MemberFunctionIdMsType.PDB_ID:
				type = new MemberFunctionIdMsType(pdb, reader);
				break;
			case BuildInfoMsType.PDB_ID:
				type = new BuildInfoMsType(pdb, reader);
				break;
			case SubstringListMsType.PDB_ID:
				type = new SubstringListMsType(pdb, reader);
				break;
			case StringIdMsType.PDB_ID:
				type = new StringIdMsType(pdb, reader);
				break;
			case UserDefinedTypeSourceAndLineMsType.PDB_ID:
				type = new UserDefinedTypeSourceAndLineMsType(pdb, reader);
				break;
			case UserDefinedTypeModuleSourceAndLineMsType.PDB_ID:
				type = new UserDefinedTypeModuleSourceAndLineMsType(pdb, reader);
				//TODO: more work
				break;

			// This should never happen (unless we missed something
			// or MSFT has added new in a version we do not handle.
			default:
				// Commented out because we have issue with VC42 file header of IPI.
//              System.out.println(reader.dump());
//				assert false;
				type = new UnknownMsType(pdb, reader, dataTypeId);
				break;
		}

		return type;
	}

}
