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
package ghidra.feature.vt.gui.task;

import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.CommentChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionNameChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionSignatureChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.LabelChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.ReplaceDataChoices;
import ghidra.framework.options.ToolOptions;

import java.util.Collection;

/**
 * A task to apply markup items using the indicated options. If a markup item is set to 
 * "Do Not Apply" this will force the item to be applied by forcing a default option for 
 * that markup type.
 */
public class ForceApplyMarkupItemTask extends ApplyMarkupItemTask {

	public ForceApplyMarkupItemTask(VTSession session, Collection<VTMarkupItem> markupItems,
			ToolOptions options) {
		super("Default Apply Markup Items", session, markupItems, forceOptions(options));
	}

	private static ToolOptions forceOptions(ToolOptions options) {
		ToolOptions vtOptions = options.copy();
		// (Force Apply) Transform any markup types that are excluded to their default apply type.
		if (vtOptions.getEnum(DATA_MATCH_DATA_TYPE, DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE) == ReplaceDataChoices.EXCLUDE) {
			vtOptions.setEnum(DATA_MATCH_DATA_TYPE, DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE);
		}
		if (vtOptions.getEnum(LABELS, DEFAULT_OPTION_FOR_LABELS) == LabelChoices.EXCLUDE) {
			vtOptions.setEnum(LABELS, DEFAULT_OPTION_FOR_LABELS);
		}
		if (vtOptions.getEnum(FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME) == FunctionNameChoices.EXCLUDE) {
			vtOptions.setEnum(FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME);
		}

		if (vtOptions.getEnum(FUNCTION_SIGNATURE, DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE) == FunctionSignatureChoices.EXCLUDE) {
			vtOptions.setEnum(FUNCTION_SIGNATURE, DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE);
		}
		// This leaves the options alone that are the individual parts of the function signature.
		// So this will force the signature to apply, but only as the individual options already indicate.

		if (vtOptions.getEnum(PLATE_COMMENT, DEFAULT_OPTION_FOR_PLATE_COMMENTS) == CommentChoices.EXCLUDE) {
			vtOptions.setEnum(PLATE_COMMENT, DEFAULT_OPTION_FOR_PLATE_COMMENTS);
		}
		if (vtOptions.getEnum(PRE_COMMENT, DEFAULT_OPTION_FOR_PRE_COMMENTS) == CommentChoices.EXCLUDE) {
			vtOptions.setEnum(PRE_COMMENT, DEFAULT_OPTION_FOR_PRE_COMMENTS);
		}
		if (vtOptions.getEnum(END_OF_LINE_COMMENT, DEFAULT_OPTION_FOR_EOL_COMMENTS) == CommentChoices.EXCLUDE) {
			vtOptions.setEnum(END_OF_LINE_COMMENT, DEFAULT_OPTION_FOR_EOL_COMMENTS);
		}
		if (vtOptions.getEnum(REPEATABLE_COMMENT, DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS) == CommentChoices.EXCLUDE) {
			vtOptions.setEnum(REPEATABLE_COMMENT, DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS);
		}
		if (vtOptions.getEnum(POST_COMMENT, DEFAULT_OPTION_FOR_POST_COMMENTS) == CommentChoices.EXCLUDE) {
			vtOptions.setEnum(POST_COMMENT, DEFAULT_OPTION_FOR_POST_COMMENTS);
		}

		return vtOptions;
	}
}
