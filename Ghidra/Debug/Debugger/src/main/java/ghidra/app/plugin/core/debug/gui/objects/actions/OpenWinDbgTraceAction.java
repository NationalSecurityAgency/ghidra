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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class OpenWinDbgTraceAction extends ImportExportAsAction {

	protected ImageIcon ICON_TRACE = ResourceManager.loadImage("images/text-xml.png");
	private ActionContext context;

	public OpenWinDbgTraceAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("OpenTrace", tool, owner, provider);
		fileExt = ".run";
		fileMode = GhidraFileChooserMode.FILES_AND_DIRECTORIES;
		setMenuBarData(new MenuData(new String[] { IMPORT, "from trace" }, ICON_TRACE, GROUP));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, InputEvent.ALT_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "open_trace"));
		provider.addLocalAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		this.context = context;
		return provider.isInstance(context, TargetLauncher.class);
	}

	@Override
	protected void doAction(ObjectContainer container, File f) {
		if (f == null) {
			return;
		}
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				String[] args = new String[2];
				args[0] = ".opendump";
				args[1] = f.getAbsolutePath();
				AtomicReference<TargetLauncher> launcher = new AtomicReference<>();
				AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
					TargetObject obj = provider.getObjectFromContext(context);
					DebugModelConventions.findSuitable(TargetLauncher.class, obj).handle(seq::next);
				}, launcher).then(seq -> {
					launcher.get()
							.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, args))
							.handle(seq::next);
					seq.exit();
				}).finish();
			}
		});
	}

}
