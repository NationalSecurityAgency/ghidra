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
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * QuickFix for renaming datatypes.
 */
public class RenameDataTypeQuickFix extends RenameQuickFix {

	private DataType dataType;

	/**
	 * Constructor
	 * @param program the program containing the datatype to be renamed
	 * @param dataType the datatype being renamed
	 * @param newName the new name for the datatype
	 */
	public RenameDataTypeQuickFix(Program program, DataType dataType, String newName) {
		super(program, dataType.getName(), newName);
		this.dataType = dataType;
		if (!canRename()) {
			setStatus(QuickFixStatus.ERROR, "This datatype doesn't support renaming");
		}
		checkDuplicate();
	}

	private void checkDuplicate() {
		CategoryPath categoryPath = dataType.getCategoryPath();
		DataTypeManager dtm = dataType.getDataTypeManager();
		Category category = dtm.getCategory(categoryPath);
		DataType existing = category.getDataType(replacement);
		if (existing != null) {
			setStatus(QuickFixStatus.WARNING, "Datatype with name \"" + replacement +
				"\" already exists in category \"" + category.getCategoryPathName() + "\"");
		}
	}

	@Override
	public String getItemType() {
		return "Datatype";
	}

	@Override
	public Address getAddress() {
		return null;
	}

	private boolean canRename() {
		return !(dataType instanceof BuiltInDataType ||
			dataType instanceof MissingBuiltInDataType || dataType instanceof Array ||
			dataType instanceof Pointer);
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
		return dataType.getName();
	}

	@Override
	public void execute() {
		try {
			dataType.setName(replacement);
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
}
