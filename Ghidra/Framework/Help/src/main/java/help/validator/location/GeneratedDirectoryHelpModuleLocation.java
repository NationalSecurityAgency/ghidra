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
package help.validator.location;

import java.io.File;

import help.validator.model.GhidraTOCFile;

/**
 * Represents a directory that holds generated content.  At the time of writing, the only known 
 * such input is the 'tips of the day' html file that is created from a text file.
 */
public class GeneratedDirectoryHelpModuleLocation extends DirectoryHelpModuleLocation {

	public GeneratedDirectoryHelpModuleLocation(File file) {
		super(file);
	}

	@Override
	public GhidraTOCFile loadSourceTOCFile() {
		// Generated directories are not full help directories with TOC source files. 
		return null;
	}

	@Override
	public boolean isHelpInputSource() {
		return false;
	}

}
