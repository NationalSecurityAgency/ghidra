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

import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskLauncher;

/**
 * The AddToProgramDialog is essentially the same as the ImporterDialog with a few exceptions.  One
 * difference is that the language and destination folder/name are not enabled and are initialized
 * to the existing program to which the imported data will be added.  Also, the Ok callback
 * is overridden to add the data to the current program instead of creating a new program.
 */
public class AddToProgramDialog extends ImporterDialog {

	private Program addToProgram;

	/**
	 * Construct a new AddToProgramDialog.
	 * @param tool the tool containing the currently open program.
	 * @param fsrl the FileSystemURL for where the imported data can be read.
	 * @param loaderMap the loaders and their corresponding load specifications
	 * @param byteProvider the ByteProvider from which the bytes from the source can be read.
	 *        The dialog takes ownership of the ByteProvider and it will be closed when
	 *        the dialog is closed
	 * @param addToProgram the program to which the newly imported data will be added
	 */
	protected AddToProgramDialog(PluginTool tool, FSRL fsrl, LoaderMap loaderMap,
			ByteProvider byteProvider, Program addToProgram) {
		super("Add To Program:  " + fsrl.getPath(), tool, loaderMap, byteProvider, null);
		this.addToProgram = addToProgram;
		folderNameTextField.setText(getFolderName(addToProgram));
		filenameTextField.setText(addToProgram.getName());
		setSelectedLanguage(getLanguageSpec());
		languageTextField.setEnabled(false);
		folderNameTextField.setEnabled(false);
		folderButton.setEnabled(false);
		languageButton.setEnabled(false);
		filenameTextField.setEnabled(false);
		validateFormInput();
	}

	@Override
	protected boolean validateFormInput() {

		setOkEnabled(false);
		optionsButton.setEnabled(false);
		Loader loader = getSelectedLoader();
		if (loader == null) {
			setStatusText("Please select a format.");
			return false;
		}
		if (!loader.supportsLoadIntoProgram()) {
			setStatusText(loader.getName() + " does not support add to program.");
			return false;
		}
		optionsButton.setEnabled(true);

		LoadSpec loadSpec = getSelectedLoadSpec(loader);

		String result =
			loader.validateOptions(byteProvider, loadSpec, getOptions(loadSpec), addToProgram);

		if (result != null) {
			setStatusText(result);
			return false;
		}

		setStatusText("");
		setOkEnabled(true);
		return true;
	}

	@Override
	protected boolean isSupported(Loader loader) {
		return loader.supportsLoadIntoProgram();
	}

	@Override
	protected void selectedLoaderChanged() {
		options = null;
		validateFormInput();
	}

	@Override
	protected void okCallback() {
		Loader selectedLoader = getSelectedLoader();
		LoadSpec selectedLoadSpec = getSelectedLoadSpec(selectedLoader);

		if (options == null) {
			options = selectedLoader.getDefaultOptions(byteProvider, selectedLoadSpec, null, true);
		}
		TaskLauncher.launchNonModal("Import File", monitor -> {
			ImporterUtilities.addContentToProgram(tool, addToProgram, fsrl, selectedLoadSpec,
				options, monitor);
		});
		close();
	}

	@Override
	protected List<Option> getOptions(LoadSpec loadSpec) {
		if (options != null) {
			return options;
		}
		return loadSpec.getLoader().getDefaultOptions(byteProvider, loadSpec, addToProgram, true);
	}

	/**
	 * Retrieves the current language/compiler spec from the program that will be added to.
	 * @return the current language/compiler spec from the program that will be added to.
	 */
	LanguageCompilerSpecPair getLanguageSpec() {
		LanguageID languageId = addToProgram.getLanguageID();
		CompilerSpecID compilerSpecId = addToProgram.getCompilerSpec().getCompilerSpecID();
		return new LanguageCompilerSpecPair(languageId, compilerSpecId);
	}

	private String getFolderName(Program program) {
		DomainFile domainFile = program.getDomainFile();
		DomainFolder parent = domainFile.getParent();
		if (parent == null) {
			return "";
		}
		return parent.toString();
	}
}
