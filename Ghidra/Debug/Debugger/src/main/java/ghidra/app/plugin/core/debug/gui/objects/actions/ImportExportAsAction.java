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
package ghidra.app.plugin.core.debug.gui.objects.actions;

import java.io.File;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;

public abstract class ImportExportAsAction extends DockingAction {

	protected PluginTool tool;
	protected DebuggerObjectsProvider provider;
	protected String fileExt;
	protected GhidraFileChooserMode fileMode;

	protected String IMPORT = "Import...";
	protected String GROUP = "ImportExport";

	public ImportExportAsAction(String name, PluginTool tool, String owner,
			DebuggerObjectsProvider provider) {
		super(name, owner);
		this.tool = tool;
		this.provider = provider;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Object obj = context.getContextObject();
		ObjectContainer sel = provider.getSelectedContainer(obj);
		return sel != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Object contextObject = context.getContextObject();
		ObjectContainer container = provider.getSelectedContainer(contextObject);

		GhidraFileChooser chooser = new GhidraFileChooser(provider.getComponent());
		chooser.setFileFilter(new GhidraFileFilter() {

			@Override
			public String getDescription() {
				return "*" + fileExt;
			}

			@Override
			public boolean accept(File file, GhidraFileChooserModel chooserModel) {
				if (file.getName().endsWith(fileExt)) {
					return true;
				}
				return file.isDirectory();
			}
		});
		chooser.setFileSelectionMode(fileMode);

		chooser.setCurrentDirectory(Application.getUserSettingsDirectory());

		File f = chooser.getSelectedFile();
		if (chooser.wasCancelled() || f == null) { // Redundant? Meh, it's cheap.
			return;
		}
		doAction(container, f);
	}

	protected abstract void doAction(ObjectContainer container, File f);

}
