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
package ghidra.app.util.bin.format.dwarf4.external;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import java.io.File;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "DWARF External Debug Files",
	description = "Configure how the DWARF analyzer finds external debug files."
)
//@formatter:on
public class DWARFExternalDebugFilesPlugin extends Plugin {

	private static final String EXT_DEBUG_FILES_OPTION = "ExternalDebugFiles";
	private static final String SEARCH_LOCATIONS_LIST_OPTION =
		EXT_DEBUG_FILES_OPTION + ".searchLocations";

	public DWARFExternalDebugFilesPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {
		new ActionBuilder("DWARF External Debug Config", this.getName())
				.menuPath(ToolConstants.MENU_EDIT, "DWARF External Debug Config")
				.menuGroup(ToolConstants.TOOL_OPTIONS_MENU_GROUP)
				.onAction(ac -> showConfigDialog())
				.buildAndInstall(tool);
	}

	private void showConfigDialog() {
		// Let the user pick a single directory, and configure a ".build-id/" search location
		// and a recursive dir search location at that directory, as well as a
		// same-dir search location to search the program's import directory.
		GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
		chooser.setMultiSelectionEnabled(false);
		chooser.setApproveButtonText("Select");
		chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		chooser.setTitle("Select External Debug Files Directory");
		File selectedDir = chooser.getSelectedFile();
		if (selectedDir == null) {
			return;
		}

		BuildIdSearchLocation bisl = new BuildIdSearchLocation(new File(selectedDir, ".build-id"));
		LocalDirectorySearchLocation ldsl = new LocalDirectorySearchLocation(selectedDir);
		SameDirSearchLocation sdsl = new SameDirSearchLocation(new File("does not matter"));

		ExternalDebugFilesService edfs = new ExternalDebugFilesService(List.of(bisl, ldsl, sdsl));
		saveExternalDebugFilesService(edfs);
	}

	/**
	 * Get a new instance of {@link ExternalDebugFilesService} using the previously saved 
	 * information (via {@link #saveExternalDebugFilesService(ExternalDebugFilesService)}).
	 *  
	 * @param context created via {@link SearchLocationRegistry#newContext(ghidra.program.model.listing.Program)}
	 * @return new {@link ExternalDebugFilesService} instance
	 */
	public static ExternalDebugFilesService getExternalDebugFilesService(
			SearchLocationCreatorContext context) {
		SearchLocationRegistry searchLocRegistry = SearchLocationRegistry.getInstance();
		String searchPathStr = Preferences.getProperty(SEARCH_LOCATIONS_LIST_OPTION, "", true);
		String[] pathParts = searchPathStr.split(";");
		List<SearchLocation> searchLocs = new ArrayList<>();
		for (String part : pathParts) {
			if (!part.isBlank()) {
				SearchLocation searchLoc = searchLocRegistry.createSearchLocation(part, context);
				if (searchLoc != null) {
					searchLocs.add(searchLoc);
				}
			}
		}
		if (searchLocs.isEmpty()) {
			// default to search the same directory as the program
			searchLocs.add(SameDirSearchLocation.create(null, context));
		}
		return new ExternalDebugFilesService(searchLocs);
	}

	/**
	 * Serializes an {@link ExternalDebugFilesService} to a string and writes to the Ghidra
	 * global preferences.
	 * 
	 * @param service the {@link ExternalDebugFilesService} to commit to preferences
	 */
	public static void saveExternalDebugFilesService(ExternalDebugFilesService service) {
		if (service != null) {
			String path = service.getSearchLocations()
					.stream()
					.map(SearchLocation::getName)
					.collect(Collectors.joining(";"));
			Preferences.setProperty(SEARCH_LOCATIONS_LIST_OPTION, path);
		}
		else {
			Preferences.setProperty(SEARCH_LOCATIONS_LIST_OPTION, null);
		}
	}

}
