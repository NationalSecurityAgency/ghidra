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
 * QuickFix for updating structure or union field comments
 */
public class UpdateFieldCommentQuickFix extends CompositeFieldQuickFix {
	private String fieldName;

	/**
	 * Constructor
	 * @param program the program containing the enum value whose comment is to be updated
	 * @param composite the structure or union whose field comment is to be changed
	 * @param fieldName  the field name whose comment is to be changed
	 * @param ordinal the ordinal of the field being renamed with its containing composite
	 * @param original the original comment of the field
	 * @param newComment the new comment for the field
	 */
	public UpdateFieldCommentQuickFix(Program program, Composite composite, String fieldName,
			int ordinal, String original, String newComment) {
		super(program, composite, ordinal, original, newComment);
		this.fieldName = fieldName;
	}

	@Override
	public String getActionName() {
		return "Update";
	}

	@Override
	public String getItemType() {
		return "Field Comment";
	}

	@Override
	public String doGetCurrent() {
		DataTypeComponent component = findComponent(fieldName);
		return component == null ? null : component.getComment();
	}

	@Override
	public void execute() {
		DataTypeComponent component = findComponent(fieldName);
		try {
			component.setComment(replacement);
		}
		catch (Exception e) {
			setStatus(QuickFixStatus.ERROR, "Update field comment failed: " + e.getMessage());
		}
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return null;
	}

	@Override
	protected String getFieldName() {
		return fieldName;
	}

}
