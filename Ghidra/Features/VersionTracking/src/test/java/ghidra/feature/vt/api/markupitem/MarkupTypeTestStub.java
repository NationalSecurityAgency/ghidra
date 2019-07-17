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
package ghidra.feature.vt.api.markupitem;

import java.util.Collections;
import java.util.List;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;

public class MarkupTypeTestStub extends VTMarkupType {
	public static final VTMarkupType INSTANCE = new MarkupTypeTestStub();

	private MarkupTypeTestStub() {
		super("Test");
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<VTMarkupItem> createMarkupItems(VTAssociation association) {
		return Collections.EMPTY_LIST;

	}

	@Override
	public Address validateDestinationAddress(VTAssociation association, Address sourceAddress,
			Address suggestedDestinationAddress) {
		return suggestedDestinationAddress;
	}

	@Override
	public void unapplyMarkup(VTMarkupItem markupItem) throws VersionTrackingApplyException {
		// no-op
	}

	@Override
	public boolean supportsApplyAction(VTMarkupItemApplyActionType applyAction) {
		return true;
	}

	@Override
	public boolean supportsAssociationType(VTAssociationType matchType) {
		return true;
	}

	@Override
	public Stringable getSourceValue(VTAssociation association, Address source) {
		return null;
	}

	@Override
	public ProgramLocation getSourceLocation(VTAssociation association, Address sourceAddress) {
		return null;
	}

	@Override
	public String getDisplayName() {
		return "Test Markup Migrator";
	}

	@Override
	public Stringable getCurrentDestinationValue(VTAssociation association,
			Address destinationAddress) {
		return null;
	}

	@Override
	public Stringable getOriginalDestinationValue(VTAssociation association,
			Address destinationAddress) {
		return getCurrentDestinationValue(association, destinationAddress);
	}

	@Override
	public ProgramLocation getDestinationLocation(VTAssociation association,
			Address destinationAddress) {
		return null;
	}

	@Override
	public VTMarkupItemApplyActionType getApplyAction(ToolOptions options) {
		return VTMarkupItemApplyActionType.REPLACE;
	}

	@Override
	public Options convertOptionsToForceApplyOfMarkupItem(VTMarkupItemApplyActionType applyAction,
			ToolOptions applyOptions) {
		ToolOptions convertedOptions = applyOptions.copy();
		switch (applyAction) {

			case ADD:
				convertedOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.ADD);
				convertedOptions.setEnum(VTOptionDefines.END_OF_LINE_COMMENT,
					CommentChoices.APPEND_TO_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.PRE_COMMENT,
					CommentChoices.APPEND_TO_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.POST_COMMENT,
					CommentChoices.APPEND_TO_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.REPEATABLE_COMMENT,
					CommentChoices.APPEND_TO_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.PLATE_COMMENT,
					CommentChoices.APPEND_TO_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.FUNCTION_NAME, FunctionNameChoices.ADD);
				convertedOptions.setEnum(VTOptionDefines.PARAMETER_COMMENTS,
					CommentChoices.APPEND_TO_EXISTING);
				break;

			case ADD_AS_PRIMARY:
				convertedOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.ADD_AS_PRIMARY);
				convertedOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
					FunctionNameChoices.ADD_AS_PRIMARY);
				break;

			case REPLACE_DEFAULT_ONLY:
				convertedOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.REPLACE_DEFAULT_ONLY);
				convertedOptions.setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
					ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
				convertedOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
					FunctionNameChoices.REPLACE_DEFAULT_ONLY);
				convertedOptions.setEnum(VTOptionDefines.FUNCTION_RETURN_TYPE,
					ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
				break;

			case REPLACE_FIRST_ONLY:
				convertedOptions.setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
					ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
				break;

			case REPLACE:
				convertedOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.REPLACE_ALL);
				convertedOptions.setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
					ReplaceDataChoices.REPLACE_ALL_DATA);
				convertedOptions.setEnum(VTOptionDefines.END_OF_LINE_COMMENT,
					CommentChoices.OVERWRITE_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.PRE_COMMENT,
					CommentChoices.OVERWRITE_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.POST_COMMENT,
					CommentChoices.OVERWRITE_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.REPEATABLE_COMMENT,
					CommentChoices.OVERWRITE_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.PLATE_COMMENT,
					CommentChoices.OVERWRITE_EXISTING);
				convertedOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
					FunctionNameChoices.REPLACE_ALWAYS);
				convertedOptions.setEnum(VTOptionDefines.FUNCTION_RETURN_TYPE,
					ParameterDataTypeChoices.REPLACE);
				convertedOptions.setEnum(VTOptionDefines.FUNCTION_SIGNATURE,
					FunctionSignatureChoices.REPLACE);
				convertedOptions.setEnum(VTOptionDefines.CALLING_CONVENTION,
					CallingConventionChoices.NAME_MATCH);
				convertedOptions.setEnum(VTOptionDefines.CALL_FIXUP, ReplaceChoices.REPLACE);
				convertedOptions.setEnum(VTOptionDefines.INLINE, ReplaceChoices.REPLACE);
				convertedOptions.setEnum(VTOptionDefines.NO_RETURN, ReplaceChoices.REPLACE);
				convertedOptions.setEnum(VTOptionDefines.VAR_ARGS, ReplaceChoices.REPLACE);
				convertedOptions.setEnum(VTOptionDefines.PARAMETER_DATA_TYPES,
					ParameterDataTypeChoices.REPLACE);
				convertedOptions.setEnum(VTOptionDefines.PARAMETER_NAMES,
					SourcePriorityChoices.REPLACE);
				convertedOptions.setEnum(VTOptionDefines.PARAMETER_COMMENTS,
					CommentChoices.OVERWRITE_EXISTING);
				break;
		}
		return convertedOptions;
	}

	@Override
	public boolean applyMarkup(VTMarkupItem markupItem, ToolOptions markupOptions)
			throws VersionTrackingApplyException {
		return true;
	}

	@Override
	public boolean hasSameSourceAndDestinationValues(VTMarkupItem markupItem) {
		return false;
	}
}
