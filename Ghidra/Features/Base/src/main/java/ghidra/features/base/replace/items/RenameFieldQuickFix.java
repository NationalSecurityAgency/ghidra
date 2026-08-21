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

import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * QuickFix for renaming structure or union fields
 */
public class RenameFieldQuickFix extends CompositeFieldQuickFix {

	/**
	 * Constructor
	 * @param program the program containing the structure or union field to be renamed
	 * @param composite the composite whose field is being renamed
	 * @param ordinal the ordinal of the field being renamed with its containing composite
	 * @param original the original name of the field
	 * @param newName the new name for the enum value
	 */
	public RenameFieldQuickFix(Program program, Composite composite, int ordinal, String original,
			String newName) {
		super(program, composite, ordinal, original, newName);
	}

	@Override
	public String getActionName() {
		return "Rename";
	}

	@Override
	public String getItemType() {
		return "Field Name";
	}

	@Override
	public String doGetCurrent() {
		DataTypeComponent component = getComponent();
		return component == null ? null : component.getFieldName();
	}

	private DataTypeComponent getComponent() {
		DataTypeComponent component = findComponent(original);
		if (component == null) {
			component = findComponent(replacement);
		}
		return component;
	}

	@Override
	public void execute() {
		try {
			DataTypeComponent component = getComponent();
			if (component != null) {
				component.setFieldName(replacement);
			}
		}
		catch (Exception e) {
			setStatus(QuickFixStatus.ERROR, "Rename field failed: " + e.getMessage());
		}
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return null;
	}

	@Override
	protected String getFieldName() {
		return current;
	}

}
