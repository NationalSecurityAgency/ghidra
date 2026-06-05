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
package ghidra.app.plugin.core.datamgr.actions;

import java.util.List;
import java.util.stream.Collectors;

import ghidra.program.model.data.DataType;
import ghidra.util.HelpLocation;

/**
 * Confirmation dialog for merging two datatypes. The dialog displays the resulting datatype along
 * with the two being merged in a side by side view. Also displays any warning messages associated
 * with the merge.
 */
public class DataTypeMergeConfirmationDialog extends AbstractDataTypeMergeDialog {

	private boolean cancelled = false;

	public DataTypeMergeConfirmationDialog(DataType result, DataType mergeTo, DataType mergeFrom,
			List<String> warnings) {
		super("Merge Data Types?", result, mergeTo, mergeFrom, join(warnings));
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Merge_Confirmation"));
		addApplyButton();
		addCancelButton();
	}

	@Override
	protected void applyCallback() {
		close();
	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		close();
	}

	public boolean wasCancelled() {
		return cancelled;
	}

	@Override
	protected String getMessageAreaTitle() {
		return "Warnings:";
	}

	private static String join(List<String> lines) {
		if (lines.isEmpty()) {
			return null;
		}
		return lines.stream().collect(Collectors.joining("\n"));
	}

}
