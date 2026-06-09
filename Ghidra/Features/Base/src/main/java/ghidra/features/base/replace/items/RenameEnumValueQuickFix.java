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
package ghidra.features.base.replace.items;

import java.util.Map;

import ghidra.app.services.DataTypeManagerService;
import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.features.base.replace.RenameQuickFix;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * QuickFix for renaming enum values.
 */
public class RenameEnumValueQuickFix extends RenameQuickFix {

	private Enum enumm;
	private long enumValue;

	/**
	 * Constructor
	 * @param program the program containing the enum to be renamed
	 * @param enumDt the enum whose value is being renamed
	 * @param valueName the enum value name being changed
	 * @param newName the new name for the enum value
	 */
	public RenameEnumValueQuickFix(Program program, Enum enumDt, String valueName,
			String newName) {
		super(program, valueName, newName);
		this.enumm = enumDt;
		this.enumValue = enumDt.getValue(valueName);
		validate();
	}

	@Override
	public String getItemType() {
		return "Enum Value";
	}

	private void validate() {
		if (enumm.contains(replacement)) {
			setStatus(QuickFixStatus.WARNING,
				"New name not allowed because it duplicates an existing value name");
		}
	}

	@Override
	protected void statusChanged(QuickFixStatus newStatus) {
		if (newStatus == QuickFixStatus.NONE) {
			validate();
		}
	}

	@Override
	public Address getAddress() {
		return null;
	}

	@Override
	public String getPath() {
		return enumm.getPathName();
	}

	@Override
	public String doGetCurrent() {
		if (enumm.contains(original)) {
			return original;
		}
		else if (enumm.contains(replacement)) {
			return replacement;
		}
		return null;
	}

	@Override
	public void execute() {
		try {
			enumm.add(replacement, enumValue);
			enumm.remove(original);
		}
		catch (Exception e) {
			setStatus(QuickFixStatus.ERROR, "Rename enum value failed: " + e.getMessage());
		}
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return null;
	}

	@Override
	public Map<String, String> getCustomToolTipData() {
		return Map.of("Enum", enumm.getPathName());
	}

	@Override
	protected boolean navigateSpecial(ServiceProvider services, boolean fromSelectionChange) {
		DataTypeManagerService dtmService = services.getService(DataTypeManagerService.class);
		if (dtmService == null) {
			return false;
		}

		dtmService.setDataTypeSelected(enumm);

		if (!fromSelectionChange) {
			dtmService.edit(enumm);
		}
		return true;
	}
}
