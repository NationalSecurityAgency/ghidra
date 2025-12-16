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
package ghidra.features.base.replace;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.program.model.listing.Program;

/**
 * Base class for QuickFix objects that rename Ghidra program elements.
 */
public abstract class RenameQuickFix extends QuickFix {

	/**
	 * Constructor
	 * @param program the program this applies to
	 * @param name the original name of the element to rename
	 * @param newName the new name for the element when this QuickFix is applied.
	 */
	public RenameQuickFix(Program program, String name, String newName) {
		super(program, name, newName);
		validateReplacementName();
	}

	protected void validateReplacementName() {
		if (replacement.isBlank()) {
			setStatus(QuickFixStatus.ERROR, "Can't rename to \"\"");
		}
	}

	@Override
	public String getActionName() {
		return "Rename";
	}

}
