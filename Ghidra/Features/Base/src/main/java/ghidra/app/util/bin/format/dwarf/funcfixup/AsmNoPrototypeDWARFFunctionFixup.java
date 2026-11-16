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
package ghidra.app.util.bin.format.dwarf.funcfixup;

import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.DWARFFunction.CommitMode;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * Adjust functions in a assembler compile unit to avoid locking asm funcs to an empty param
 * list.
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_NORMAL_EARLY)
public class AsmNoPrototypeDWARFFunctionFixup implements DWARFFunctionFixup {

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc) throws DWARFException {
		DIEAggregate diea = dfunc.diea;
		int cuLang = diea.getCompilationUnit().getLanguage();
		if (cuLang == DWARFSourceLanguage.DW_LANG_Mips_Assembler && dfunc.isBlankSignature() &&
			DWARFFunction.hasNoSignatureInformation(dfunc.diea)) {
			// the need for this check will mostly be avoided by DWARFFunctionImporter's similar
			// check for empty signatures and its use of prototypeFuncStubs to find matching info
			// to override the empty info  
			dfunc.signatureCommitMode = CommitMode.NO_PARAMS;
		}
	}

}
