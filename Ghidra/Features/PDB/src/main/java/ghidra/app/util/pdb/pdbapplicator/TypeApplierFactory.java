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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;

/**
 * Pseudo-factory for creating the {@link MsTypeApplier} for the {@link AbstractMsType}
 * indicated by the AbstractMsType and also its {@link RecordNumber}. This class also performs
 * caching of the applier by its RecordNumber.
 */
public class TypeApplierFactory {

	private PdbApplicator applicator;
	private Map<RecordNumber, MsTypeApplier> appliersByRecordNumber;

	TypeApplierFactory(PdbApplicator applicator) {
		this.applicator = applicator;
		appliersByRecordNumber = new HashMap<>();
	}

	//==============================================================================================
	MsTypeApplier getApplierSpec(RecordNumber recordNumber, Class<? extends MsTypeApplier> expected)
			throws PdbException {
		MsTypeApplier applier = getTypeApplier(recordNumber);
		if (!expected.isInstance(applier)) {
			throw new PdbException(applier.getClass().getSimpleName() + " seen where " +
				expected.getSimpleName() + " expected for record number " + recordNumber);
		}
		return applier;
	}

	MsTypeApplier getApplierOrNoTypeSpec(RecordNumber recordNumber,
			Class<? extends MsTypeApplier> expected) throws PdbException {
		MsTypeApplier applier = getTypeApplier(recordNumber);
		if (!expected.isInstance(applier)) {
			if (!(applier instanceof PrimitiveTypeApplier &&
				((PrimitiveTypeApplier) applier).isNoType())) {
				throw new PdbException(applier.getClass().getSimpleName() + " seen where " +
					expected.getSimpleName() + " expected for record number " + recordNumber);
			}
		}
		return applier;
	}

	MsTypeApplier getTypeApplier(RecordNumber recordNumber) {
		MsTypeApplier applier = appliersByRecordNumber.get(recordNumber);
		if (applier == null) {
			applier = getTypeApplier(applicator.getPdb().getTypeRecord(recordNumber));
			appliersByRecordNumber.put(recordNumber, applier);
		}
		return applier;
	}

	//==============================================================================================
	MsTypeApplier getTypeApplier(AbstractMsType type) {
		if (type == null) {
			applicator.appendLogMsg("PDB Warning: No AbstractMsType for getTypeApplier");
			return null;
		}
		MsTypeApplier applier = null;
		try {
			switch (type.getPdbId()) {
				case -1: // must be careful, as we chose the -1 for PrimitiveMsType
					applier = new PrimitiveTypeApplier(applicator, (PrimitiveMsType) type);
					break;

				// 0x0000 block
				case Modifier16MsType.PDB_ID:
					applier = new ModifierTypeApplier(applicator, (Modifier16MsType) type);
					break;
				case Pointer16MsType.PDB_ID:
					applier = new PointerTypeApplier(applicator, (Pointer16MsType) type);
					break;
				case Array16MsType.PDB_ID:
					applier = new ArrayTypeApplier(applicator, (Array16MsType) type);
					break;
				case Class16MsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (Class16MsType) type);
					break;
				case Structure16MsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (Structure16MsType) type);
					break;
				case Union16MsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (Union16MsType) type);
					break;
				case Enum16MsType.PDB_ID:
					applier = new EnumTypeApplier(applicator, (Enum16MsType) type);
					break;
				case Procedure16MsType.PDB_ID:
					applier = new ProcedureTypeApplier(applicator, (Procedure16MsType) type);
					break;
				case MemberFunction16MsType.PDB_ID:
					applier =
						new MemberFunctionTypeApplier(applicator, (MemberFunction16MsType) type);
					break;
//				case VtShapeMsType.PDB_ID:
//					applier = new VtShapeTypeApplier(applicator, (VtShapeMsType) type);
//					break;
//				case Cobol016MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case Cobol1MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case BasicArray16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case LabelMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case NullMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case NotTranMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArray16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case VirtualFunctionTablePath16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case PrecompiledType16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case EndPrecompiledTypeMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case OemDefinableString16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case TypeServerStMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;

				// 0x0200 block
//				case Skip16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case ArgumentsList16MsType.PDB_ID:
					applier =
						new ArgumentsListTypeApplier(applicator, (ArgumentsList16MsType) type);
					break;
//				case DefaultArguments16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case ListMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case FieldList16MsType.PDB_ID:
					applier = new FieldListTypeApplier(applicator, type);
					break;
//				case DerivedClassList16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case Bitfield16MsType.PDB_ID:
					applier = new BitfieldTypeApplier(applicator, (Bitfield16MsType) type);
					break;
//				case MethodList16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArrayConstBoundsUpper16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArrayConstBoundsLowerUpper16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArrayVarBoundsUpper16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArrayVarBoundsLowerUpper16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case ReferencedSymbolMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;

				// 0x400 block
				case BaseClass16MsType.PDB_ID:
					applier = new BaseClassTypeApplier(applicator, type);
					break;
				case VirtualBaseClass16MsType.PDB_ID:
					applier = new BaseClassTypeApplier(applicator, type);
					break;
				case IndirectVirtualBaseClass16MsType.PDB_ID:
					applier = new BaseClassTypeApplier(applicator, type);
					break;
				case EnumerateStMsType.PDB_ID:
					applier = new EnumerateTypeApplier(applicator, (EnumerateStMsType) type);
					break;
//				case FriendFunction16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case Index16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case Member16MsType.PDB_ID:
					applier = new MemberTypeApplier(applicator, (Member16MsType) type);
					break;
//				case StaticMember16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case OverloadedMethod16MsType.PDB_ID:
					// See note in "default" case regarding NoTypeApplier
					applier = new NoTypeApplier(applicator, type);
					break;
				case NestedType16MsType.PDB_ID:
					applier = new NestedTypeApplier(applicator, type);
					break;
				case VirtualFunctionTablePointer16MsType.PDB_ID:
					applier = new VirtualFunctionTablePointerTypeApplier(applicator, type);
					break;
//				case FriendClass16MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case OneMethod16MsType.PDB_ID:
					// See note in "default" case regarding NoTypeApplier
					applier = new NoTypeApplier(applicator, type);
					break;
				case VirtualFunctionTablePointerWithOffset16MsType.PDB_ID:
					applier = new VirtualFunctionTablePointerTypeApplier(applicator, type);
					break;

				// 0x1000 block
				case ModifierMsType.PDB_ID:
					applier = new ModifierTypeApplier(applicator, (ModifierMsType) type);
					break;
				case PointerMsType.PDB_ID:
					applier = new PointerTypeApplier(applicator, (PointerMsType) type);
					break;
				case ArrayStMsType.PDB_ID:
					applier = new ArrayTypeApplier(applicator, (ArrayStMsType) type);
					break;
				case ClassStMsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (ClassStMsType) type);
					break;
				case StructureStMsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (StructureStMsType) type);
					break;
				case UnionStMsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (UnionStMsType) type);
					break;
				case EnumStMsType.PDB_ID:
					applier = new EnumTypeApplier(applicator, (EnumStMsType) type);
					break;
				case ProcedureMsType.PDB_ID:
					applier = new ProcedureTypeApplier(applicator, (ProcedureMsType) type);
					break;
				case MemberFunctionMsType.PDB_ID:
					applier =
						new MemberFunctionTypeApplier(applicator, (MemberFunctionMsType) type);
					break;
//				case Cobol0MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case BasicArrayMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArrayStMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case VirtualFunctionTablePathMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case PrecompiledTypeStMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case OemDefinableStringMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case AliasStMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case OemDefinableString2MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//
				// 0x1200 block
//				case SkipMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case ArgumentsListMsType.PDB_ID:
					applier = new ArgumentsListTypeApplier(applicator, (ArgumentsListMsType) type);
					break;
//				case DefaultArgumentsStMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case FieldListMsType.PDB_ID:
					applier = new FieldListTypeApplier(applicator, type);
					break;
//				case DerivedClassListMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case BitfieldMsType.PDB_ID:
					applier = new BitfieldTypeApplier(applicator, (BitfieldMsType) type);
					break;
//				case MethodListMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArrayConstBoundsUpperMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArrayConstBoundsLowerUpperMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArrayVarBoundsUpperMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DimensionedArrayVarBoundsLowerUpperMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;

				// 0x1400 block
				case BaseClassMsType.PDB_ID:
					applier = new BaseClassTypeApplier(applicator, type);
					break;
				case VirtualBaseClassMsType.PDB_ID:
					applier = new BaseClassTypeApplier(applicator, type);
					break;
				case IndirectVirtualBaseClassMsType.PDB_ID:
					applier = new BaseClassTypeApplier(applicator, type);
					break;
//				case FriendFunctionStMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case IndexMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case MemberStMsType.PDB_ID:
					applier = new MemberTypeApplier(applicator, (MemberStMsType) type);
					break;
//				case StaticMemberStMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case OverloadedMethodStMsType.PDB_ID:
					// See note in "default" case regarding NoTypeApplier
					applier = new NoTypeApplier(applicator, type);
					break;
				case NestedTypeStMsType.PDB_ID:
					applier = new NestedTypeApplier(applicator, type);
					break;
				case VirtualFunctionTablePointerMsType.PDB_ID:
					applier = new VirtualFunctionTablePointerTypeApplier(applicator, type);
					break;
//				case FriendClassMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case OneMethodStMsType.PDB_ID:
					// See note in "default" case regarding NoTypeApplier
					applier = new NoTypeApplier(applicator, type);
					break;
				case VirtualFunctionTablePointerWithOffsetMsType.PDB_ID:
					applier = new VirtualFunctionTablePointerTypeApplier(applicator, type);
					break;
				case NestedTypeExtStMsType.PDB_ID:
					applier = new NestedTypeApplier(applicator, type);
					break;
//				case MemberModifyStMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case ManagedStMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;

				// 0x1500 block 
//				case TypeServerMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case EnumerateMsType.PDB_ID:
					applier = new EnumerateTypeApplier(applicator, (EnumerateMsType) type);
					break;
				case ArrayMsType.PDB_ID:
					applier = new ArrayTypeApplier(applicator, (ArrayMsType) type);
					break;
				case ClassMsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (ClassMsType) type);
					break;
				case StructureMsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (StructureMsType) type);
					break;
				case UnionMsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (UnionMsType) type);
					break;
				case EnumMsType.PDB_ID:
					applier = new EnumTypeApplier(applicator, (EnumMsType) type);
					break;
//				case DimensionedArrayMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case PrecompiledTypeMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case AliasMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case DefaultArgumentsMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case FriendFunctionMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case MemberMsType.PDB_ID:
					applier = new MemberTypeApplier(applicator, (MemberMsType) type);
					break;
//				case StaticMemberMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case OverloadedMethodMsType.PDB_ID:
					// See note in "default" case regarding NoTypeApplier
					applier = new NoTypeApplier(applicator, type);
					break;
				case NestedTypeMsType.PDB_ID:
					applier = new NestedTypeApplier(applicator, type);
					break;
				case OneMethodMsType.PDB_ID:
					// See note in "default" case regarding NoTypeApplier
					applier = new NoTypeApplier(applicator, type);
					break;
				case NestedTypeExtMsType.PDB_ID:
					applier = new NestedTypeApplier(applicator, type);
					break;
//				case MemberModifyMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case ManagedMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case TypeServer2MsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case StridedArrayMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case HighLevelShaderLanguageMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case ModifierExMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case InterfaceMsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (InterfaceMsType) type);
					break;
//				case BaseInterfaceMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case VectorMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case MatrixMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case VirtualFunctionTableMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;

				// 0x1600 block 
//				case FunctionIdMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case MemberFunctionIdMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case BuildInfoMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case SubstringListMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
//				case StringIdMsType.PDB_ID:
//					// Not evaluated/implemented yet.
//					break;
				case UserDefinedTypeSourceAndLineMsType.PDB_ID:
					applier = new UdtSourceLineTypeApplier(applicator, type);
					break;
				case UserDefinedTypeModuleSourceAndLineMsType.PDB_ID:
					applier = new UdtSourceLineTypeApplier(applicator, type);
					break;
				case Class19MsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (Class19MsType) type);
					break;
				case Structure19MsType.PDB_ID:
					applier = new CompositeTypeApplier(applicator, (Structure19MsType) type);
					break;
				// TODO: the following three types are only hypothetical and might be in the wrong
				// order with the wrong PDB_IDs and the wrong internal elements and parsing.
				// These are here as partial implementations until they are seen and can be
				// cleaned up and put into service.
//				case Union19MsType.PDB_ID:
//					applier = new CompositeTypeApplier(applicator, (Union19MsType) type);
//					break;
//				case Enum19MsType.PDB_ID:
//					applier = new EnumTypeApplier(applicator, (Enum19MsType) type);
//					break;
//				case Interface19MsType.PDB_ID:
//					// TODO InterfaceTypeApplier does not exist, and the two types we would
//					// want to send it would need to either be abstracted to one abstract type
//					// or a generic AbstractMsType would have to be sent and then verified
//					// internal to the applier.
//					applier = new InterfaceTypeApplier(applicator, (Interface19MsType) type);
//					break;

				// If all of the above are enabled, this should never happen (unless we missed
				// something or MSFT has added new in a version we do not handle.
				default:
					applier = new NoTypeApplier(applicator, type);
					// Only adding to this cannotApplyTypes list here, and not in other
					//  places (above) where we might currently be using a NoTypeApplier.
					//  Using a NoTypeApplier in other places (above) might just be a placeholder
					//  until we craft the specific ways in which we would like to "apply" the
					//  data type information.
					applicator.getPdbApplicatorMetrics().witnessCannotApplyDataType(type);
					break;
			}
		}
		catch (IllegalArgumentException e) {
			try {
				applier = new NoTypeApplier(applicator, type);
			}
			catch (IllegalArgumentException e2) {
				// We did a null check above on type, so this state should not happen.
			}
			RecordNumber recNum = type.getRecordNumber();
			String msg = (recNum == null) ? "record" : recNum.toString();
			String message = "GhidraException on " + msg + " with PdbId " + type.getPdbId() + ": " +
				e.getMessage();
			applicator.appendLogMsg(message);
			applicator.pdbLogAndInfoMessage(this, message);
		}
		return applier;
	}

}
