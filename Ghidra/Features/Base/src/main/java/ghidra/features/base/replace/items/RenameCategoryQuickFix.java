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
import ghidra.program.model.data.Category;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * QuickFix for renaming datatype categories.
 */
public class RenameCategoryQuickFix extends RenameQuickFix {

	private Category category;

	/**
	 * Constructor
	 * @param program the program containing the category to be renamed
	 * @param category the category to be renamed
	 * @param newName the new name for the category
	 */
	public RenameCategoryQuickFix(Program program, Category category, String newName) {
		super(program, category.getName(), newName);
		this.category = category;
		checkForDuplicates();
	}

	private void checkForDuplicates() {
		Category parent = category.getParent();
		if (parent == null) {
			return;
		}
		if (parent.getCategory(replacement) != null) {
			setStatus(QuickFixStatus.WARNING,
				"The name \"" + replacement + "\" already exists in category \"" +
					parent.getCategoryPathName() + "\"");
		}
	}

	@Override
	public void statusChanged(QuickFixStatus newStatus) {
		if (newStatus == QuickFixStatus.NONE) {
			checkForDuplicates();
		}
	}

	@Override
	public String getItemType() {
		return "datatype category";
	}

	@Override
	public Address getAddress() {
		return null;
	}

	@Override
	public String getPath() {
		return category.getParent().getCategoryPathName();
	}

	@Override
	protected String doGetCurrent() {
		return category.getName();
	}

	@Override
	protected void execute() {
		try {
			category.setName(replacement);
		}
		catch (DuplicateNameException | InvalidNameException e) {
			setStatus(QuickFixStatus.ERROR, "Rename Failed! " + e.getMessage());
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

		dtmService.setCategorySelected(category);
		return true;
	}

	@Override
	public Map<String, String> getCustomToolTipData() {
		return Map.of("Parent Path", category.getParent().getCategoryPathName());
	}

}
