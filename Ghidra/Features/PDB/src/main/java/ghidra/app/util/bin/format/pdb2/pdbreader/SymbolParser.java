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

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.util.exception.CancelledException;

/**
 * Parser for detecting the parsing the appropriate Symbol structures ({@link AbstractMsSymbol}) in
 *  the PDB.
 */
public class SymbolParser {

	//==============================================================================================
	// Internals
	//==============================================================================================
	private AbstractPdb pdb;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns the Symbols to be parsed.
	 */
	public SymbolParser(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	/**
	 * Deserializes an {@link AbstractMsSymbol} from the {@link PdbByteReader} and returns it.
	 * @param reader {@link PdbByteReader} from which to deserialize the symbol record.
	 * @return {@link AbstractMsSymbol} that was parsed.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	public AbstractMsSymbol parse(PdbByteReader reader) throws PdbException, CancelledException {
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
	 * @param symbolTypeId the PDB ID for the symbol type to be parsed.
	 * @param reader {@link PdbByteReader} from which to deserialize the symbol record.
	 * @return {@link AbstractMsSymbol} that was parsed.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	private AbstractMsSymbol parseRecord(int symbolTypeId, PdbByteReader reader)
			throws PdbException, CancelledException {

		pdb.getPdbReaderMetrics().witnessSymbolTypeId(symbolTypeId);

		AbstractMsSymbol symbol = null;
		switch (symbolTypeId) {
			// 0x0000 block
			case CompileFlagsMsSymbol.PDB_ID:
				symbol = new CompileFlagsMsSymbol(pdb, reader);
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
				symbol = new LocalSlotIndexFieldedLILStMsSymbol(pdb, reader);
				break;
			case ParameterSlotIndexFieldedLILStMsSymbol.PDB_ID:
				symbol = new ParameterSlotIndexFieldedLILStMsSymbol(pdb, reader);
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
				symbol = new ManLocOrParamReltoVFPStMsSymbol(pdb, reader);
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
				symbol = new ManLocOrParamReltoAMPStMsSymbol(pdb, reader);
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
				symbol = new LocalSlotIndexFieldedLILMsSymbol(pdb, reader);
				break;
			case ParameterSlotIndexFieldedLILMsSymbol.PDB_ID:
				symbol = new ParameterSlotIndexFieldedLILMsSymbol(pdb, reader);
				break;
			case LocalManagedDataMsSymbol.PDB_ID:
				symbol = new LocalManagedDataMsSymbol(pdb, reader);
				break;
			case GlobalManagedDataMsSymbol.PDB_ID:
				symbol = new GlobalManagedDataMsSymbol(pdb, reader);
				break;
			case ManLocOrParamReltoVFPMsSymbol.PDB_ID:
				symbol = new ManLocOrParamReltoVFPMsSymbol(pdb, reader);
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
				symbol = new ManLocOrParamReltoAMPMsSymbol(pdb, reader);
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
				symbol = new AttribLocOrParamReltoVFPMsSymbol(pdb, reader);
				break;
			case AttributedLocalOrParameterSIRMsSymbol.PDB_ID:
				symbol = new AttributedLocalOrParameterSIRMsSymbol(pdb, reader);
				break;
			case AttribLocOrParamReltoAMPMsSymbol.PDB_ID:
				symbol = new AttribLocOrParamReltoAMPMsSymbol(pdb, reader);
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
				symbol = new EnregisteredFieldOfSymbolDARMsSymbol(pdb, reader);
				break;
			case FramePointerRelativeFullScopeDARMsSymbol.PDB_ID:
				symbol = new FramePointerRelativeFullScopeDARMsSymbol(pdb, reader);
				break;
			case EnregisteredSymbolRelativeDARMsSymbol.PDB_ID:
				symbol = new EnregisteredSymbolRelativeDARMsSymbol(pdb, reader);
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
				symbol = new DeferredProcedureCallPointerTagRegDimDARMsSymbol(pdb, reader);
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
			case UnknownX1166MsSymbol.PDB_ID:
				// We have recently seen 1167 and 1168, which implies that 1166 must exist.
				symbol = new UnknownX1166MsSymbol(pdb, reader);
				break;
			case UnknownX1167MsSymbol.PDB_ID:
				// We have not investigated this type yet, but have seen it in VS2017 output.
				symbol = new UnknownX1167MsSymbol(pdb, reader);
				break;
			case UnknownX1168MsSymbol.PDB_ID:
				// We have not investigated this type yet, but have seen it in VS2017 output.
				symbol = new UnknownX1168MsSymbol(pdb, reader);
				break;
			default:
				// This should never happen (unless we missed something
				// or MSFT has added new in a version we do not handle.
				symbol = new UnknownMsSymbol(pdb, reader, symbolTypeId);
				break;
		}

		return symbol;
	}

}
