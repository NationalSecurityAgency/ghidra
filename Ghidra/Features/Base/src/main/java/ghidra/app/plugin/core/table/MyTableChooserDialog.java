/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.table;

import ghidra.app.nav.Navigatable;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.program.model.listing.Program;

public class MyTableChooserDialog extends TableChooserDialog {

	private final TableServicePlugin plugin;

	public MyTableChooserDialog(TableServicePlugin plugin, TableChooserExecutor executor,
			Program program, String name, Navigatable navigatable, boolean isModal) {

		super(plugin.getTool(), executor, program, name, navigatable, isModal);
		this.plugin = plugin;
	}

	public MyTableChooserDialog(TableServicePlugin plugin, TableChooserExecutor executor,
			Program program, String name, Navigatable navigatable) {

		this(plugin, executor, program, name, navigatable, false);
	}

	@Override
	public void close() {
		super.close();
		plugin.removeDialog(this);
	}
}
