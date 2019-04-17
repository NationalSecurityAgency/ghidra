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
import java.nio.file.Path;

import javax.help.HelpSet;

import ghidra.util.exception.AssertException;
import help.validator.model.GhidraTOCFile;

public class DirectoryHelpModuleLocation extends HelpModuleLocation {

	public DirectoryHelpModuleLocation(File file) {
		super(file.toPath());
	}

	@Override
	public boolean isHelpInputSource() {
		return true;
	}

	@Override
	public HelpSet loadHelpSet() {
		// help sets are generated from a directory module structure, thus one does not exist here
		return null;
	}

	@Override
	public GhidraTOCFile loadSourceTOCFile() {
		Path sourceTocPath = helpDir.resolve("TOC_Source.xml");
		try {
			return GhidraTOCFile.createGhidraTOCFile(sourceTocPath);
		}
		catch (Exception e) {
			throw new AssertException("Unexpected error loading source TOC file!: " + sourceTocPath,
				e);
		}
	}
}
