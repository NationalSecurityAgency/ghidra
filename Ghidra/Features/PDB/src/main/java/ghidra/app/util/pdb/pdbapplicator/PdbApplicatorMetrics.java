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

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

/**
 * Metrics captured during the application of a PDB.  This is a Ghidra class separate from the
 *  PDB API that we have crafted to help us quantify and qualify the ability apply the PDB
 *  to a {@link DataTypeManager} and/or {@link Program}. 
 */
public class PdbApplicatorMetrics {

	/**
	 * List of symbols seen (by their ID) as Global symbols.
	 */
	private static Set<Integer> expectedGlobalSymbols = new HashSet<>();
	static {
		// AbstractReferenceMsSymbol
		expectedGlobalSymbols.add(DataReferenceStMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(DataReferenceMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(LocalProcedureReferenceMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(LocalProcedureReferenceStMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(ProcedureReferenceMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(ProcedureReferenceStMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(AnnotationReferenceMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(TokenReferenceToManagedProcedureMsSymbol.PDB_ID);

		// AbstractDataMsSymbol
		expectedGlobalSymbols.add(GlobalData16MsSymbol.PDB_ID);
		expectedGlobalSymbols.add(GlobalData3216MsSymbol.PDB_ID);
		expectedGlobalSymbols.add(GlobalData32MsSymbol.PDB_ID);
		expectedGlobalSymbols.add(GlobalData32StMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(LocalData16MsSymbol.PDB_ID);
		expectedGlobalSymbols.add(LocalData3216MsSymbol.PDB_ID);
		expectedGlobalSymbols.add(LocalData32MsSymbol.PDB_ID);
		expectedGlobalSymbols.add(LocalData32StMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(GlobalManagedDataMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(GlobalManagedDataStMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(LocalManagedDataMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(LocalManagedDataStMsSymbol.PDB_ID);

		// AbstractUserDefinedTypeMsSymbol
		expectedGlobalSymbols.add(CobolUserDefinedType16MsSymbol.PDB_ID);
		expectedGlobalSymbols.add(CobolUserDefinedTypeMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(CobolUserDefinedTypeStMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(UserDefinedType16MsSymbol.PDB_ID);
		expectedGlobalSymbols.add(UserDefinedTypeMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(UserDefinedTypeStMsSymbol.PDB_ID);

		// AbstractConstantMsSymbol
		expectedGlobalSymbols.add(Constant16MsSymbol.PDB_ID);
		expectedGlobalSymbols.add(ConstantMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(ConstantStMsSymbol.PDB_ID);
		expectedGlobalSymbols.add(ManagedConstantMsSymbol.PDB_ID);
	}

	/**
	 * List of symbols seen (by their ID) as Public symbols.
	 */
	private static Set<Integer> expectedLinkerSymbols = new HashSet<>();
	static {
		expectedLinkerSymbols.add(PeCoffSectionMsSymbol.PDB_ID);
		expectedLinkerSymbols.add(TrampolineMsSymbol.PDB_ID);
		expectedLinkerSymbols.add(ObjectNameMsSymbol.PDB_ID);
		expectedLinkerSymbols.add(Compile3MsSymbol.PDB_ID);
		expectedLinkerSymbols.add(Compile2MsSymbol.PDB_ID);
		expectedLinkerSymbols.add(Compile2StMsSymbol.PDB_ID);
		expectedLinkerSymbols.add(EnvironmentBlockMsSymbol.PDB_ID);
	}

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
	public void witnessCannotApplyDataType(AbstractMsType type) {
		cannotApplyTypes.add(type.getClass());
	}

	/**
	 * Method to capture symbol type that cannot be applied.
	 * @param symbol The symbol type witnessed.
	 */
	public void witnessCannotApplySymbolType(AbstractMsSymbol symbol) {
		cannotApplySymbols.add(symbol.getClass());
	}

	/**
	 * Method to capture symbol type that was unexpected as a Global symbol.
	 * @param symbol The symbol type witnessed.
	 */
	public void witnessGlobalSymbolType(AbstractMsSymbol symbol) {
		if (!expectedGlobalSymbols.contains(symbol.getPdbId())) {
			unexpectedGlobalSymbols.add(symbol.getClass());
		}
	}

	/**
	 * Method to capture symbol type that was unexpected as a Public symbol.
	 * @param symbol The symbol type witnessed.
	 */
	public void witnessPublicSymbolType(AbstractMsSymbol symbol) {
		if (!(symbol instanceof AbstractPublicMsSymbol)) {
			unexpectedPublicSymbols.add(symbol.getClass());
		}
	}

	/**
	 * Method to capture symbol type that was unexpected as a Linker symbol.
	 * @param symbol The symbol type witnessed.
	 */
	public void witnessLinkerSymbolType(AbstractMsSymbol symbol) {
		if (!expectedLinkerSymbols.contains(symbol.getPdbId())) {
			// do nothing for now
		}
	}

	/**
	 * Method to capture witnessing of Enumerate narrowing.
	 */
	public void witnessEnumerateNarrowing() {
		witnessEnumerateNarrowing = true;
	}

	/**
	 * Method to capture unusual this pointer types.
	 * @param applier The {@AbstractMsTypeApplier} for the supposed this pointer.
	 */
	public void witnessMemberFunctionThisPointer(AbstractMsTypeApplier applier) {
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
	public void witnessMemberFunctionThisPointerUnderlyingType(AbstractMsTypeApplier applier) {
		if (applier instanceof CompositeTypeApplier) {
			return;
		}
		unexpectedMemberFunctionThisPointerUnderlyingTypes.add(applier.getMsType().getClass());
	}

	/**
	 * Method to capture unusual containing types for a member function.
	 * @param applier The {@AbstractMsTypeApplier} for the supposed this pointer.
	 */
	public void witnessMemberFunctionContainingType(AbstractMsTypeApplier applier) {
		if (applier instanceof CompositeTypeApplier) {
			return;
		}
		unexpectedMemberFunctionContainerTypes.add(applier.getMsType().getClass());
	}

	//==============================================================================================

	/**
	 * Return some post-processing metrics for applying the PDB
	 * @return {@link String} of pretty output.
	 */
	public String getPostProcessingReport() {
		StringBuilder builder = new StringBuilder();
		builder.append("===Begin PdbApplicatorMetrics Report===\n");
		builder.append(reportNonappliableTypes());
		builder.append(reportUnunsualThisPointerTypes());
		builder.append(reportUnunsualThisPointerUnderlyingTypes());
		builder.append(reportUnunsualMemberFunctionContainerTypes());
		builder.append(reportNonappliableSymbols());
		builder.append(reportUnexpectedPublicSymbols());
		builder.append(reportUnexpectedGlobalSymbols());
		builder.append(reportEnumerateNarrowing());
		builder.append("====End PdbApplicatorMetrics Report====\n");
		return builder.toString();
	}

	private String reportNonappliableTypes() {
		StringBuilder builder = new StringBuilder();
		for (Class<? extends AbstractMsType> clazz : cannotApplyTypes) {
			builder.append("Could not apply one or more instances of PDB data type: " +
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
			builder.append("Could not apply one or more instances of PDB symbol type: " +
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
