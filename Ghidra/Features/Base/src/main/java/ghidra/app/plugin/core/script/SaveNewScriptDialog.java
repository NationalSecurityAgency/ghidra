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
package ghidra.app.plugin.core.script;

import java.awt.Component;
import java.io.File;

import generic.jar.ResourceFile;
import ghidra.util.HelpLocation;

class SaveNewScriptDialog extends SaveDialog {

	SaveNewScriptDialog(Component parent, String title,
			GhidraScriptComponentProvider componentProvider, ResourceFile scriptFile,
			HelpLocation help) {
		super(parent, title, componentProvider, scriptFile, help);
	}

	/**
	 * Overridden because we don't allow the user to use an existing name when creating a new
	 * script.  However, we sometimes allow that case when performing a 'Save As...'
	 */
	@Override
	protected String getDuplicateNameErrorMessage(String name) {
		if (componentProvider.getInfoManager().alreadyExists(name)) {
			return "Duplicate script name.";
		}

		File userChoice = new File(getDirectory().getFile(false), name);
		if (userChoice.exists()) {
			return "File already exists on disk.";
		}

		return null;
	}
}
