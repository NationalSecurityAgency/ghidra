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

import java.io.IOException;

import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.DWARFFunction.CommitMode;
import ghidra.program.database.data.ProgramBasedDataTypeManagerDB;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.exception.InvalidInputException;

/**
 * Adjust functions in a Rust compile unit to use Rust calling convention, ignore any information
 * about parameter storage locations.
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_NORMAL_EARLY)
public class RustDWARFFunctionFixup implements DWARFFunctionFixup {
	private String rustCC;

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc) throws DWARFException {
		DIEAggregate diea = dfunc.diea;
		int cuLang = diea.getCompilationUnit().getLanguage();
		if (cuLang == DWARFSourceLanguage.DW_LANG_Rust) {
			dfunc.callingConventionName = getRustCC(dfunc.getProgram().getGhidraProgram());
			dfunc.signatureCommitMode = CommitMode.FORMAL;
		}

	}

	private String getRustCC(Program program) throws DWARFException {
		if (rustCC == null) {
			rustCC = CompilerSpec.CALLING_CONVENTION_rustcall;
			try {
				// NOTE: this has a side effect of ensuring the rust cc is present in the program
				ProgramBasedDataTypeManagerDB dtm =
					(ProgramBasedDataTypeManagerDB) program.getDataTypeManager();
				dtm.getCallingConventionID(CompilerSpec.CALLING_CONVENTION_rustcall, false);
			}
			catch (InvalidInputException | IOException e) {
				throw new DWARFException("Unable to get Rust calling convention");
			}
		}
		return rustCC;
	}
}
