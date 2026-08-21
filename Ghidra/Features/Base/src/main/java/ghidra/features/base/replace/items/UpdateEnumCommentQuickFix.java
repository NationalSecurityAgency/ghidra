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
import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * QuickFix for updating enum value comments
 */
public class UpdateEnumCommentQuickFix extends QuickFix {

	private Enum enumm;
	private String valueName;

	/**
	 * Constructor
	 * @param program the program containing the enum value whose comment is to be updated
	 * @param enumDt the enum whose field value comment is to be changed
	 * @param valueName  the enum value name whose comment is to be changed
	 * @param newComment the new comment for the enum value
	 */
	public UpdateEnumCommentQuickFix(Program program, Enum enumDt, String valueName,
			String newComment) {
		super(program, enumDt.getComment(valueName), newComment);
		this.enumm = enumDt;
		this.valueName = valueName;
	}

	@Override
	public String getActionName() {
		return "Update";
	}

	@Override
	public String getItemType() {
		return "Enum Comment";
	}

	@Override
	public Address getAddress() {
		return null;
	}

	@Override
	public String getPath() {
		return enumm.getCategoryPath().getPath();
	}

	@Override
	public String doGetCurrent() {
		return enumm.getComment(valueName);
	}

	@Override
	public void execute() {
		try {
			long value = enumm.getValue(valueName);
			enumm.remove(valueName);
			enumm.add(valueName, value, replacement);
		}
		catch (Exception e) {
			setStatus(QuickFixStatus.ERROR, "Update enum comment failed: " + e.getMessage());
		}
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return null;
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

	@Override
	public Map<String, String> getCustomToolTipData() {
		return Map.of("Datatype", enumm.getPathName());
	}
}
