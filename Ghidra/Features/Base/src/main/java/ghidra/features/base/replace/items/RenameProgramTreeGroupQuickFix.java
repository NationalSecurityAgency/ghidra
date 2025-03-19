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

import ghidra.app.services.ProgramTreeService;
import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.features.base.replace.RenameQuickFix;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;

/**
 * QuickFix for renaming program tree groups (modules or fragments)
 */
public class RenameProgramTreeGroupQuickFix extends RenameQuickFix {

	private String path;
	private Group group;

	/**
	 * Constructor
	 * @param program the program containing the program tree group to be renamed
	 * @param group the program tree module or fragment to be renamed
	 * @param newName the new name for the memory block
	 */
	public RenameProgramTreeGroupQuickFix(Program program, Group group,
			String newName) {
		super(program, group.getName(), newName);
		this.group = group;
		this.path = computePath();
		checkForDuplicates();
	}

	private void checkForDuplicates() {
		ProgramModule[] parents = group.getParents();
		if (parents != null) {
			for (ProgramModule module : parents) {
				if (module.getIndex(replacement) >= 0) {
					setStatus(QuickFixStatus.WARNING,
						"The name \"" + replacement + "\" already exists in module \"" +
							module.getName() + "\"");
				}
			}
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
		if (group instanceof ProgramFragment) {
			return "Program Tree Fragment";
		}
		return "Program Tree Module";
	}

	private String computePath() {
		StringBuilder builder = new StringBuilder();
		computePath(group, builder);
		return builder.toString();
	}

	private void computePath(Group treeGroup, StringBuilder builder) {
		ProgramModule[] parents = treeGroup.getParents();
		if (parents.length > 0) {
			computePath(parents[0], builder);
			builder.append("/");
		}
		builder.append(treeGroup.getName());
	}

	@Override
	public String getPath() {
		return path;
	}

	@Override
	protected String doGetCurrent() {
		if (group.isDeleted()) {
			return null;
		}
		return group.getName();
	}

	@Override
	protected void execute() {
		try {
			group.setName(replacement);
		}
		catch (Exception e) {
			setStatus(QuickFixStatus.ERROR, "Rename Failed! " + e.getMessage());
		}
	}

	@Override
	public ProgramLocation getProgramLocation() {
		if (getAddress() != null) {
			return new ProgramLocation(program, getAddress());
		}
		return null;
	}

	@Override
	public Address getAddress() {
		return group.getMinAddress();
	}

	@Override
	protected boolean navigateSpecial(ServiceProvider services, boolean fromSelectionChange) {
		ProgramTreeService service = services.getService(ProgramTreeService.class);
		if (service == null) {
			return false;
		}
		service.setViewedTree(group.getTreeName());
		service.setGroupSelection(group.getGroupPath());
		return true;
	}

	@Override
	public Map<String, String> getCustomToolTipData() {
		return Map.of("Program Tree Path", path);
	}
}
