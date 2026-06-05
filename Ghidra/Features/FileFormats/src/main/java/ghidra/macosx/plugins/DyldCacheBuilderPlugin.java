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
package ghidra.macosx.plugins;

import java.io.IOException;

import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.dialog.AskAddrDialog;
import ghidra.app.util.opinion.DyldCacheExtractLoader;
import ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Plugin} that adds an action to build up a DYLD Cache from extracted components
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "DYLD Cache Builder",
	description = "This plugin provides actions for adding DYLD Cache components to the program"
)
//@formatter:on
public class DyldCacheBuilderPlugin extends Plugin {

	/**
	 * Creates a new {@link DyldCacheBuilderPlugin}
	 * 
	 * @param tool The {@link PluginTool} that will host/contain this {@link Plugin}
	 */
	public DyldCacheBuilderPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();

		final String addActionName = "Add To Program";
		new ActionBuilder(addActionName, getName())
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(context -> context.getProgram()
						.getExecutableFormat()
						.equals(DyldCacheExtractLoader.DYLD_CACHE_EXTRACT_NAME))
				.onAction(context -> TaskLauncher.launchModal(addActionName,
					monitor -> addMissingDyldCacheComponent(context.getLocation(), monitor)))
				.popupMenuPath("References", addActionName)
				.popupMenuGroup("Add")
				.helpLocation(new HelpLocation("ImporterPlugin", "Add_To_Program"))
				.buildAndInstall(tool);
	}

	/**
	 * Attempts to add the DYLD Cache component that resides at the given {@link ProgramLocation}'s
	 * "referred to" address
	 * 
	 * @param location The {@link ProgramLocation} where the action took place
	 * @param monitor A {@link TaskMonitor}
	 */
	private void addMissingDyldCacheComponent(ProgramLocation location, TaskMonitor monitor) {
		Program program = location.getProgram();
		Address address = location.getRefAddress();
		if (address == null) {
			AskAddrDialog dialog = new AskAddrDialog(name, "Enter address", program, null);
			if (dialog.isCanceled()) {
				return;
			}
			address = dialog.getValueAsAddress();
		}
		if (address.getAddressSpace().isExternalSpace()) {
			Msg.showInfo(this, null, name, "External locations are not currently supported");
			return;
		}
		if (program.getMemory().contains(address)) {
			Msg.showInfo(this, null, name,
				"Address %s already exists in memory".formatted(address));
			return;
		}

		try (FileSystemRef fsRef = DyldCacheExtractLoader.openDyldCache(program, monitor)) {
			DyldCacheFileSystem fs = (DyldCacheFileSystem) fsRef.getFilesystem();
			long offset = address.getOffset();
			String fsPath = fs.findAddress(offset);
			if (fsPath != null) {
				ImporterUtilities.showAddToProgramDialog(fs.getFSRL().appendPath(fsPath), program,
					tool, monitor);
			}
			else {
				Msg.showInfo(this, null, name,
					"Address %s not found in %s".formatted(address, fs.toString()));
			}
		}
		catch (CancelledException e) {
			// Do nothing
		}
		catch (IOException e) {
			Msg.showError(this, null, name, e.getMessage(), e);
		}
	}
}
