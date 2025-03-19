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
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * QuickFix for updating a datatype's description (Only supported on structures, unions, or enums)
 */
public class UpdateDataTypeDescriptionQuickFix extends QuickFix {

	private DataType dataType;

	/**
	 * Constructor
	 * @param program the program containing the datatype description to be updated.
	 * @param dataType the datatype being renamed
	 * @param newDescription the new name for the datatype
	 */
	public UpdateDataTypeDescriptionQuickFix(Program program, DataType dataType,
			String newDescription) {
		super(program, getDescription(dataType), newDescription);
		this.dataType = dataType;
	}

	@Override
	public String getItemType() {
		return "Datatype Description";
	}

	@Override
	public Address getAddress() {
		return null;
	}

	@Override
	public String getPath() {
		return dataType.getCategoryPath().getPath();
	}

	@Override
	public String doGetCurrent() {
		if (dataType.isDeleted()) {
			return null;
		}
		return getDescription(dataType);
	}

	private static String getDescription(DataType dt) {
		if (dt instanceof Composite composite) {
			return composite.getDescription();
		}
		if (dt instanceof Enum enumDataType) {
			return enumDataType.getDescription();
		}
		return null;

	}

	@Override
	public void execute() {
		try {
			if (dataType instanceof Composite composite) {
				composite.setDescription(replacement);
			}
			else if (dataType instanceof Enum enumDataType) {
				enumDataType.setDescription(replacement);
			}
		}
		catch (Exception e) {
			setStatus(QuickFixStatus.ERROR, "Rename datatype failed: " + e.getMessage());
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

		dtmService.setDataTypeSelected(dataType);

		if (!fromSelectionChange) {
			dtmService.edit(dataType);
		}
		return true;
	}

	@Override
	public Map<String, String> getCustomToolTipData() {
		return Map.of("Category", dataType.getCategoryPath().toString());
	}

	@Override
	public String getActionName() {
		return "Update";
	}
}
