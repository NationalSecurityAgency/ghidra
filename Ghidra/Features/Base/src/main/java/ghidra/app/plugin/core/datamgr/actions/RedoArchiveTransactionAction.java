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

import java.io.IOException;

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.util.Msg;

public class RedoArchiveTransactionAction extends AbstractUndoRedoArchiveTransactionAction {

	public RedoArchiveTransactionAction(DataTypeManagerPlugin plugin) {
		super("Redo", plugin);
		// Key-bind disabled by default to activation context concerns
		//setKeyBindingData(new KeyBindingData("ctrl shift Z"));
		setDescription("Redo last undone change made to data type archive");
	}

	@Override
	protected boolean canExecute(PersistentDataTypeArchive dta) {
		return dta.canRedo();
	}

	@Override
	protected String getNextName(PersistentDataTypeArchive dta) {
		return dta.getRedoName();
	}

	@Override
	protected void execute(PersistentDataTypeArchive dta) {
		try {
			dta.redo();
		}
		catch (IOException e) {
			Msg.showError(this, null, "Archive Redo Failed",
				"Failed to redo last transaction: " + dta.getName(), e);
		}
	}

}
