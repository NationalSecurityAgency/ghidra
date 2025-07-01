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
package ghidra.plugin.importer;

import static ghidra.app.util.opinion.AbstractLibrarySupportLoader.*;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.app.util.*;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;

/**
 * Dialog for editing the options for the "Load Libraries" action
 */
public class LoadLibrariesOptionsDialog extends OptionsDialog {

	public static final String TITLE = "Load Libraries";

	private ByteProvider provider;
	private Program program;
	private PluginTool tool;
	private LoadSpec loadSpec;

	/**
	 * Creates a new {@link LoadLibrariesOptionsDialog}
	 * 
	 * @param provider The {@link Program}'s bytes
	 * @param program The {@link Program} to load libraries into
	 * @param tool The tool
	 * @param loadSpec The {@link LoadSpec} that was used to load the {@link Program}
	 * @param addressFactoryService The {@link AddressFactoryService} to use
	 */
	public LoadLibrariesOptionsDialog(ByteProvider provider, Program program, PluginTool tool,
			LoadSpec loadSpec, AddressFactoryService addressFactoryService) {
		super(getLoadLibraryOptions(provider, loadSpec), optionList -> loadSpec.getLoader()
				.validateOptions(provider, loadSpec, optionList, null),
			addressFactoryService);
		setTitle(TITLE);
		this.provider = provider;
		this.program = program;
		this.tool = tool;
		this.loadSpec = loadSpec;
	}

	@Override
	protected void okCallback() {
		TaskLauncher.launchNonModal(TITLE, monitor -> {
			super.okCallback();
			Object consumer = new Object();
			MessageLog messageLog = new MessageLog();
			try (LoadResults<? extends DomainObject> loadResults = loadSpec.getLoader()
						.load(provider, program.getDomainFile().getName(), tool.getProject(),
							program.getDomainFile().getParent().getPathname(), loadSpec,
						getOptions(), messageLog, consumer, monitor)) {

				loadResults.save(monitor);
				
				// Display results
				String importMessages = messageLog.toString();
				if (!importMessages.isEmpty()) {
					if (!Loader.loggingDisabled) {
						Msg.info(ImporterUtilities.class, TITLE + ":\n" + importMessages);
					}
					MultiLineMessageDialog.showModalMessageDialog(null, TITLE, "Results",
						importMessages, MultiLineMessageDialog.INFORMATION_MESSAGE);
				}
				else {
					Msg.showInfo(this, null, TITLE, "The program has no libraries.");
				}
			}
			catch (CancelledException e) {
				// no need to show a message
			}
			catch (Exception e) {
				Msg.showError(LoadLibrariesOptionsDialog.class, tool.getActiveWindow(), TITLE,
					"Error loading libraries for: " + program.getName(), e);
			}
		});
	}

	/**
	 * Gets a {@link List} of {@link Option}s that relate to loading libraries
	 * 
	 * @param provider The {@link ByteProvider} of the program
	 * @param loadSpec The {@link LoadSpec} that was used to load the program
	 * @return A {@link List} of {@link Option}s that relate to loading libraries
	 * @see AbstractLibrarySupportLoader
	 */
	private static List<Option> getLoadLibraryOptions(ByteProvider provider, LoadSpec loadSpec) {
		List<Option> options = new ArrayList<>();
		for (Option option : loadSpec.getLoader()
				.getDefaultOptions(provider, loadSpec, null, false)) {
			switch (option.getName()) {
				case LOAD_ONLY_LIBRARIES_OPTION_NAME:
				case LOAD_LIBRARY_OPTION_NAME:
					option.setValue(true);
				case LINK_EXISTING_OPTION_NAME:
				case LINK_SEARCH_FOLDER_OPTION_NAME:
				case LIBRARY_SEARCH_PATH_DUMMY_OPTION_NAME:
				case LIBRARY_DEST_FOLDER_OPTION_NAME:
					options.add(option);
					break;
				default:
					break;

			}
		}
		return options;
	}
}
