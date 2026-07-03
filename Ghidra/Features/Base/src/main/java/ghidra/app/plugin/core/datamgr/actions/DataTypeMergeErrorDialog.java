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

import ghidra.program.model.data.DataType;
import ghidra.util.HelpLocation;

/**
 * Dialog for showing datatype merge errors. The dialog shows the error message and a display
 * of the two datatypes that couldn't be merged.
 */
public class DataTypeMergeErrorDialog extends AbstractDataTypeMergeDialog {

	public DataTypeMergeErrorDialog(DataType mergeTo, DataType mergeFrom, String error) {
		super("Merge Failed", null, mergeTo, mergeFrom, error);
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Merge_Error"));
		addOKButton();
	}

	@Override
	protected void okCallback() {
		close();
	}

	@Override
	protected String getMessageAreaTitle() {
		return "Merge Failed:";
	}
}
