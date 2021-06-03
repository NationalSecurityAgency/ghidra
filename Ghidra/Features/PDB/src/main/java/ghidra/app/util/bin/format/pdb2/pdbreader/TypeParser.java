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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.Objects;

import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
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

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns the Symbols to be parsed.
	 */
	public TypeParser(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	/**
	 * Deserializes an {@link AbstractMsType} from the {@link PdbByteReader} and returns it.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param recordNumber {@link RecordNumber} of the record.
	 * @return {@link AbstractMsType} parsed.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	public AbstractMsType parseRecord(PdbByteReader reader, RecordNumber recordNumber)
			throws PdbException, CancelledException {
		AbstractMsType result = parse(reader, AbstractMsType.class);
		result.setRecordNumber(recordNumber);
		return result;
	}

	/**
	 * Deserializes an {@link AbstractMsType} from the {@link PdbByteReader} and returns it
	 * as a {@link MsTypeField}.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @return {@link MsTypeField} parsed.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	public MsTypeField parseField(PdbByteReader reader) throws PdbException, CancelledException {
		MsTypeField result = parse(reader, MsTypeField.class);
		return result;
	}

	/**
	 * Deserializes an {@link AbstractMsType} from the {@link PdbByteReader} and returns it.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @return {@link AbstractMsType} parsed.
	 * @throws PdbException upon error parsing dataTypeId.
	 * @throws CancelledException Upon user cancellation.
	 */
	public AbstractMsType parse(PdbByteReader reader) throws PdbException, CancelledException {
		AbstractMsType result = parse(reader, AbstractMsType.class);
		return result;
	}

	/**
	 * Deserialized data type ID and parsable indicated by the ID and returns the type
	 *  required type expected.  Upon failure, message is logged and BadMsType is returned.
	 * @param <T> the required type to be returned.  IMPORTANT:  T must only be one of:
	 *  {@link AbstractMsType} or {@link MsTypeField} or something else in common with
	 *  {@link BadMsType}, otherwise a Bad Cast Exception might occur.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param requiredClass the required type to be returned. 
	 * @return an instance of type T or type T version of BadMsType. IMPORTANT: See restriction
	 *  on T.
	 * @throws PdbException upon error parsing dataTypeId.
	 * @throws CancelledException Upon user cancellation.
	 */
	private <T> T parse(PdbByteReader reader, Class<T> requiredClass)
			throws PdbException, CancelledException {
		int dataTypeId = reader.parseUnsignedShortVal();
		try {
			IdMsParsable parsable = parse(reader, dataTypeId);
			if (requiredClass.isInstance(parsable)) {
				return requiredClass.cast(parsable);
			}
			PdbLog.logSerializationItemClassMismatch(parsable, requiredClass, dataTypeId);
		}
		catch (PdbException e) {
			PdbLog.logDeserializationFailure(reader, dataTypeId, e);
		}
		return requiredClass.cast(new BadMsType(pdb, dataTypeId));
	}

	/**
	 * Deserializes an {@link AbstractMsType} from the {@link PdbByteReader} and returns it.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param dataTypeId the PDB ID for the symbol type to be parsed.
	 * @return {@link AbstractMsType} parsed.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	private IdMsParsable parse(PdbByteReader reader, int dataTypeId)
			throws PdbException, CancelledException {

		pdb.getPdbReaderMetrics().witnessDataTypeId(dataTypeId);

		AbstractMsType type = null;
		switch (dataTypeId) {
			// 0x0000 block
			case Modifier16MsType.PDB_ID:
				type = new Modifier16MsType(pdb, reader);
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
			case Class19MsType.PDB_ID:
				type = new Class19MsType(pdb, reader);
				break;
			case Structure19MsType.PDB_ID:
				type = new Structure19MsType(pdb, reader);
				break;
			// TODO: the following three types are only hypothetical and might be in the wrong
			// order with the wrong PDB_IDs and the wrong internal elements and parsing.
			// These are here as partial implementations until they are seen and can be
			// cleaned up and put into service.
//			case Union19MsType.PDB_ID:
//				type = new Union19MsType(pdb, reader);
//				break;
//			case Enum19MsType.PDB_ID:
//				type = new Enum19MsType(pdb, reader);
//				break;
//			case Interface19MsType.PDB_ID:
//				type = new Interface19MsType(pdb, reader);
//				break;
			default:
				// This should never happen (unless we missed something
				// or MSFT has added new in a version we do not handle.
				type = new UnknownMsType(pdb, reader, dataTypeId);
				break;
		}

		return type;
	}

}
