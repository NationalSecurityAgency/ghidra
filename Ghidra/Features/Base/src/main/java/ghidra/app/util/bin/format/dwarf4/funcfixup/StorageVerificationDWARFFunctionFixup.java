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
package ghidra.app.util.bin.format.dwarf4.funcfixup;

import ghidra.app.util.bin.format.dwarf4.next.DWARFFunction;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunction.CommitMode;
import ghidra.app.util.bin.format.dwarf4.next.DWARFVariable;
import ghidra.program.model.listing.Function;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * Downgrades the function's signature commit mode to FORMAL-param-info-only if there are
 * problems with param storage info.
 * <p>
 * Does not check the function's return value storage as that typically won't have information
 * because DWARF does not specify that.
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_LAST - 1)
public class StorageVerificationDWARFFunctionFixup implements DWARFFunctionFixup {

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc, Function gfunc) {
		boolean storageIsGood = true;
		for (DWARFVariable param : dfunc.params) {
			if (param.isMissingStorage() && !param.isZeroByte()) {
				storageIsGood = false;
				break;
			}

			// downgrade to formal if the location info for the param starts somewhere inside the
			// function instead of at the entry point
			if (!param.isLocationValidOnEntry()) {
				storageIsGood = false;
				break;
			}
		}
		if (!storageIsGood) {
			dfunc.signatureCommitMode = CommitMode.FORMAL;
		}
	}

}
