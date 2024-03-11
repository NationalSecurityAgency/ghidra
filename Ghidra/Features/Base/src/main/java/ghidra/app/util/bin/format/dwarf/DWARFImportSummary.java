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
package ghidra.app.util.bin.format.dwarf;

import java.util.*;

import ghidra.util.Msg;

/**
 * Information about what actions were performed during a DWARF import.
 */
public class DWARFImportSummary {
	// member variables are package access
	long dataTypeElapsedMS;
	long funcsElapsedMS;
	long totalElapsedMS;

	int dataTypesAdded;
	int funcsAdded;
	int funcsUpdated;
	int funcSignaturesAdded;
	int globalVarsAdded;
	Set<Integer> unknownRegistersEncountered = new HashSet<>();
	Set<String> relocationErrorVarDefs = new HashSet<>();
	int varFitError;
	int varDynamicRegisterError;
	int varDWARFExpressionValue;
	int exprReadError;
	Set<String> typeRemappings = new HashSet<>();
	int paramZeroLenDataType;
	Set<Integer> dwarfVers = new HashSet<>();
	int compUnitCount;
	int dieCount;
	Set<String> compDirs = new HashSet<>();
	List<String> compNames = new ArrayList<>();
	Set<String> producers = new HashSet<>();
	Set<String> sourceLangs = new HashSet<>();

	/**
	 * Writes summary information to the {@link Msg} log.
	 */
	public void logSummaryResults() {
		if (totalElapsedMS > 0) {
			Msg.info(this, "DWARF ver%s, %d compUnits, %d DIES, import - total elapsed: %dms"
					.formatted(getSortedSet(dwarfVers).toString(), compUnitCount, dieCount,
						totalElapsedMS));
		}
		if (dataTypeElapsedMS > 0) {
			Msg.info(this,
				String.format("DWARF data type import - elapsed: %dms", dataTypeElapsedMS));
		}
		if (funcsElapsedMS > 0) {
			Msg.info(this,
				String.format("DWARF func & symbol import - elapsed: %dms", funcsElapsedMS));
		}
		if (dataTypesAdded > 0) {
			Msg.info(this, String.format("DWARF types imported: %d", dataTypesAdded));
		}
		if (funcsAdded > 0) {
			Msg.info(this, String.format("DWARF funcs added: %d", funcsAdded));
		}
		if (funcSignaturesAdded > 0) {
			Msg.info(this,
				String.format("DWARF function signatures added: %d", funcSignaturesAdded));
		}
		if (!compDirs.isEmpty()) {
			Msg.info(this, "DWARF compile dirs: " + getSortedSet(compDirs).toString());
		}
		if (!producers.isEmpty()) {
			Msg.info(this, "DWARF producers: " + getSortedSet(producers));
		}
		if (!sourceLangs.isEmpty()) {
			Msg.info(this, "DWARF source languages: " + getSortedSet(sourceLangs));
		}
		for (String s : compNames) {
			Msg.info(this, "DWARF compUnit: " + s);
		}

		if (!typeRemappings.isEmpty()) {
			Msg.error(this,
				"DWARF data type remappings (DWARF data type definitions that changed meaning in different compile units):");
			Msg.error(this, "  Data type -> changed to -> Data Type");
			int x = 0;
			for (String s : typeRemappings) {
				Msg.error(this, "  " + s);
				if (x++ > 1000) {
					Msg.error(this, "...omitting " + (typeRemappings.size() - 1000) +
						" additional type remapping warnings.");
					break;
				}
			}
		}

		if (!relocationErrorVarDefs.isEmpty()) {
			Msg.error(this, "DWARF static variables with missing address info:");
			Msg.error(this, "  [Variable symbolic name  : variable data type]");
			for (String varDef : relocationErrorVarDefs) {
				Msg.error(this, "  " + varDef);
			}
		}

		if (varFitError > 0) {
			Msg.error(this,
				"DWARF variable definitions that failed because the data type was too large for the defined register location: " +
					varFitError);
		}

		if (varDynamicRegisterError > 0) {
			Msg.error(this,
				"DWARF variable definitions that failed because they depended on the dynamic value of a register: " +
					varDynamicRegisterError);
		}

		if (varDWARFExpressionValue > 0) {
			Msg.error(this,
				"DWARF variable definitions that failed because they are computed pseudo variables: " +
					varDWARFExpressionValue);
		}

		if (paramZeroLenDataType > 0) {
			Msg.error(this, "DWARF zero-length parameters: " + paramZeroLenDataType);
		}
		if (exprReadError > 0) {
			Msg.error(this, "DWARF expression failed to read: " + exprReadError);
		}
	}

	private <T extends Comparable<T>> List<T> getSortedSet(Set<T> set) {
		List<T> result = new ArrayList<>(set);
		Collections.sort(result);
		return result;
	}

	void addCompunitInfo(List<DWARFCompilationUnit> compUnits) {
		for (DWARFCompilationUnit cu : compUnits) {
			String compileDirectory = cu.getCompileDirectory();
			if (compileDirectory != null && !compileDirectory.isBlank()) {
				compDirs.add(compileDirectory);
			}
			String name = cu.getName();
			if (name != null && !name.isBlank()) {
				compNames.add(name);
			}
			String prod = cu.getProducer();
			if (prod != null && !prod.isBlank()) {
				producers.add(prod);
			}
			int lang = cu.getLanguage();
			if (lang != -1) {
				sourceLangs.add(DWARFUtil.toString(DWARFSourceLanguage.class, lang));
			}
		}

	}
}
