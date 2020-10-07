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

import java.util.HashSet;
import java.util.Set;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbLog;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Metrics captured during the application of a PDB.  This is a Ghidra class separate from the
 * PDB API that we have crafted to help us quantify and qualify the ability apply the PDB
 * to a {@link DataTypeManager} and/or {@link Program}. 
 */
public class PdbApplicatorMetrics {

	/**
	 * List of symbols seen (by their ID) as Global symbols.
	 */
	//@formatter:off
	private static final Set<Integer> EXPECTED_GLOBAL_SYMBOLS = Set.of(
		// AbstractReferenceMsSymbol
		DataReferenceStMsSymbol.PDB_ID,
		DataReferenceMsSymbol.PDB_ID,
		LocalProcedureReferenceMsSymbol.PDB_ID,
		LocalProcedureReferenceStMsSymbol.PDB_ID,
		ProcedureReferenceMsSymbol.PDB_ID,
		ProcedureReferenceStMsSymbol.PDB_ID,
		AnnotationReferenceMsSymbol.PDB_ID,
		TokenReferenceToManagedProcedureMsSymbol.PDB_ID,

		// AbstractDataMsSymbol
		GlobalData16MsSymbol.PDB_ID,
		GlobalData3216MsSymbol.PDB_ID,
		GlobalData32MsSymbol.PDB_ID,
		GlobalData32StMsSymbol.PDB_ID,
		LocalData16MsSymbol.PDB_ID,
		LocalData3216MsSymbol.PDB_ID,
		LocalData32MsSymbol.PDB_ID,
		LocalData32StMsSymbol.PDB_ID,
		GlobalManagedDataMsSymbol.PDB_ID,
		GlobalManagedDataStMsSymbol.PDB_ID,
		LocalManagedDataMsSymbol.PDB_ID,
		LocalManagedDataStMsSymbol.PDB_ID,

		// AbstractThreadStorageMsSymbol
		GlobalThreadStorage3216MsSymbol.PDB_ID,
		GlobalThreadStorage32MsSymbol.PDB_ID,
		GlobalThreadStorage32StMsSymbol.PDB_ID,
		LocalThreadStorage3216MsSymbol.PDB_ID,
		LocalThreadStorage32MsSymbol.PDB_ID,
		LocalThreadStorage32StMsSymbol.PDB_ID,
		
		// AbstractUserDefinedTypeMsSymbol
		CobolUserDefinedType16MsSymbol.PDB_ID,
		CobolUserDefinedTypeMsSymbol.PDB_ID,
		CobolUserDefinedTypeStMsSymbol.PDB_ID,
		UserDefinedType16MsSymbol.PDB_ID,
		UserDefinedTypeMsSymbol.PDB_ID,
		UserDefinedTypeStMsSymbol.PDB_ID,

		// AbstractConstantMsSymbol
		Constant16MsSymbol.PDB_ID,
		ConstantMsSymbol.PDB_ID,
		ConstantStMsSymbol.PDB_ID,
		ManagedConstantMsSymbol.PDB_ID
	);
	//@formatter:on

	/**
	 * List of symbols seen (by their ID) as Public symbols.
	 */
	//@formatter:off
	private static final Set<Integer> EXPECTED_LINKER_SYMBOLS = Set.of(	
		PeCoffSectionMsSymbol.PDB_ID,
		TrampolineMsSymbol.PDB_ID,
		ObjectNameMsSymbol.PDB_ID,
		Compile3MsSymbol.PDB_ID,
		Compile2MsSymbol.PDB_ID,
		Compile2StMsSymbol.PDB_ID,
		EnvironmentBlockMsSymbol.PDB_ID
	);
	//@formatter:on

	private Set<Class<? extends AbstractMsType>> cannotApplyTypes = new HashSet<>();
	private Set<Class<? extends AbstractMsType>> unexpectedMemberFunctionThisPointerTypes =
		new HashSet<>();
	private Set<Class<? extends AbstractMsType>> unexpectedMemberFunctionThisPointerUnderlyingTypes =
		new HashSet<>();
	private Set<Class<? extends AbstractMsType>> unexpectedMemberFunctionContainerTypes =
		new HashSet<>();
	private Set<Class<? extends AbstractMsSymbol>> cannotApplySymbols = new HashSet<>();
	private Set<Class<? extends AbstractMsSymbol>> unexpectedGlobalSymbols = new HashSet<>();
	private Set<Class<? extends AbstractMsSymbol>> unexpectedPublicSymbols = new HashSet<>();
	private boolean witnessEnumerateNarrowing = false;

	/**
	 * Method to capture data/item type that cannot be applied.
	 * @param type The data/item type witnessed.
	 */
	void witnessCannotApplyDataType(AbstractMsType type) {
		cannotApplyTypes.add(type.getClass());
	}

	/**
	 * Method to capture symbol type that cannot be applied.
	 * @param symbol The symbol type witnessed.
	 */
	void witnessCannotApplySymbolType(AbstractMsSymbol symbol) {
		cannotApplySymbols.add(symbol.getClass());
	}

	/**
	 * Method to capture symbol type that was unexpected as a Global symbol.
	 * @param symbol The symbol type witnessed.
	 */
	void witnessGlobalSymbolType(AbstractMsSymbol symbol) {
		if (!EXPECTED_GLOBAL_SYMBOLS.contains(symbol.getPdbId())) {
			unexpectedGlobalSymbols.add(symbol.getClass());
		}
	}

	/**
	 * Method to capture symbol type that was unexpected as a Public symbol.
	 * @param symbol The symbol type witnessed.
	 */
	void witnessPublicSymbolType(AbstractMsSymbol symbol) {
		if (!(symbol instanceof AbstractPublicMsSymbol)) {
			unexpectedPublicSymbols.add(symbol.getClass());
		}
	}

	/**
	 * Method to capture symbol type that was unexpected as a Linker symbol.
	 * @param symbol The symbol type witnessed.
	 */
	void witnessLinkerSymbolType(AbstractMsSymbol symbol) {
		if (!EXPECTED_LINKER_SYMBOLS.contains(symbol.getPdbId())) {
			// do nothing for now
		}
	}

	/**
	 * Method to capture witnessing of Enumerate narrowing.
	 */
	void witnessEnumerateNarrowing() {
		witnessEnumerateNarrowing = true;
	}

	/**
	 * Method to capture unusual this pointer types.
	 * @param applier The {@AbstractMsTypeApplier} for the supposed this pointer.
	 */
	void witnessMemberFunctionThisPointer(MsTypeApplier applier) {
		// We know that we have seen PrimitiveMsTypes that are pointer types.
		if (applier instanceof PointerTypeApplier) {
			return;
		}
		unexpectedMemberFunctionThisPointerTypes.add(applier.getMsType().getClass());
	}

	/**
	 * Method to capture unusual underlying types for a normal pointer for this pointer.
	 * @param applier The {@AbstractMsTypeApplier} for the supposed this pointer.
	 */
	void witnessMemberFunctionThisPointerUnderlyingType(MsTypeApplier applier) {
		if (applier instanceof CompositeTypeApplier) {
			return;
		}
		unexpectedMemberFunctionThisPointerUnderlyingTypes.add(applier.getMsType().getClass());
	}

	/**
	 * Method to capture unusual containing types for a member function.
	 * @param applier The {@AbstractMsTypeApplier} for the supposed this pointer.
	 */
	void witnessMemberFunctionContainingType(MsTypeApplier applier) {
		if (applier instanceof CompositeTypeApplier) {
			return;
		}
		unexpectedMemberFunctionContainerTypes.add(applier.getMsType().getClass());
	}

	//==============================================================================================

	/**
	 * Generate some post-processing metrics and write to log
	 */
	void logReport() {

		StringBuilder builder = new StringBuilder();

		builder.append(reportNonappliableTypes());
		builder.append(reportUnunsualThisPointerTypes());
		builder.append(reportUnunsualThisPointerUnderlyingTypes());
		builder.append(reportUnunsualMemberFunctionContainerTypes());
		builder.append(reportNonappliableSymbols());
		builder.append(reportUnexpectedPublicSymbols());
		builder.append(reportUnexpectedGlobalSymbols());
		builder.append(reportEnumerateNarrowing());

		if (builder.length() == 0) {
			return; // nothing reported
		}

		builder.insert(0, "===Begin PdbApplicatorMetrics Report===\n");
		builder.append("====End PdbApplicatorMetrics Report====\n");
		String text = builder.toString();

		Msg.info(this, text);
		PdbLog.message(text);
	}

	private String reportNonappliableTypes() {
		StringBuilder builder = new StringBuilder();
		for (Class<? extends AbstractMsType> clazz : cannotApplyTypes) {
			builder.append(
				"Could not apply one or more instances of an unsupported PDB data type: " +
					clazz.getSimpleName() + "\n");
		}
		return builder.toString();
	}

	private String reportUnunsualThisPointerTypes() {
		StringBuilder builder = new StringBuilder();
		for (Class<? extends AbstractMsType> clazz : unexpectedMemberFunctionThisPointerTypes) {
			builder.append("Unusual this pointer type: " + clazz.getSimpleName() + "\n");
		}
		return builder.toString();
	}

	private String reportUnunsualThisPointerUnderlyingTypes() {
		StringBuilder builder = new StringBuilder();
		for (Class<? extends AbstractMsType> clazz : unexpectedMemberFunctionThisPointerUnderlyingTypes) {
			builder.append("Unusual this pointer underlying type: " + clazz.getSimpleName() + "\n");
		}
		return builder.toString();
	}

	private String reportUnunsualMemberFunctionContainerTypes() {
		StringBuilder builder = new StringBuilder();
		for (Class<? extends AbstractMsType> clazz : unexpectedMemberFunctionContainerTypes) {
			builder.append("Unusual member function container: " + clazz.getSimpleName() + "\n");
		}
		return builder.toString();
	}

	private String reportNonappliableSymbols() {
		StringBuilder builder = new StringBuilder();
		for (Class<? extends AbstractMsSymbol> clazz : cannotApplySymbols) {
			builder.append(
				"Could not apply one or more instances of an unsupported PDB symbol type: " +
					clazz.getSimpleName() + "\n");
		}
		return builder.toString();
	}

	private String reportUnexpectedPublicSymbols() {
		StringBuilder builder = new StringBuilder();
		for (Class<? extends AbstractMsSymbol> clazz : unexpectedPublicSymbols) {
			builder.append("Unexpected one or more instances of PDB public symbol type: " +
				clazz.getSimpleName() + "\n");
		}
		return builder.toString();
	}

	private String reportUnexpectedGlobalSymbols() {
		StringBuilder builder = new StringBuilder();
		for (Class<? extends AbstractMsSymbol> clazz : unexpectedGlobalSymbols) {
			builder.append("Unexpected one or more instances of PDB global symbol type: " +
				clazz.getSimpleName() + "\n");
		}
		return builder.toString();
	}

	private String reportEnumerateNarrowing() {
		if (witnessEnumerateNarrowing) {
			return "Enumerate narrowing was witnessed\n";
		}
		return "";
	}

}
