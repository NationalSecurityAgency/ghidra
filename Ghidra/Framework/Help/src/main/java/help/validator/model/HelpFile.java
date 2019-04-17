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
package help.validator.model;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

import ghidra.util.exception.AssertException;
import help.HelpBuildUtils;
import help.validator.*;
import help.validator.location.HelpModuleLocation;

public class HelpFile {

	private final Path helpFile;
	private final HelpModuleLocation help;
	private final Path relativePath;

	private AnchorManager anchorManager;

	HelpFile(HelpModuleLocation help, Path file) {
		this.help = help;
		this.helpFile = file;
		this.anchorManager = new AnchorManager();
		this.relativePath = HelpBuildUtils.relativizeWithHelpTopics(file);

		cleanupHelpFile();

		parseLinks();
	}

	private void cleanupHelpFile() {
		try {
			HelpBuildUtils.cleanupHelpFileLinks(helpFile);
		}
		catch (IOException e) {
			System.err.println("Unexpected exception fixing help file links: " + e.getMessage());
			e.printStackTrace();
		}
	}

	Collection<HREF> getAllHREFs() {
		return anchorManager.getAnchorRefs();
	}

	Collection<IMG> getAllIMGs() {
		return anchorManager.getImageRefs();
	}

	public Path getRelativePath() {
		return relativePath;
	}

	public boolean containsAnchor(String anchorName) {
		AnchorDefinition anchor = anchorManager.getAnchorForName(anchorName);
		return anchor != null;
	}

	public Map<String, List<AnchorDefinition>> getDuplicateAnchorsByID() {
		return anchorManager.getDuplicateAnchorsByID();
	}

	public AnchorDefinition getAnchorDefinition(Path helpPath) {
		Map<String, AnchorDefinition> anchorsByHelpPath = anchorManager.getAnchorsByHelpPath();
		return anchorsByHelpPath.get(helpPath.toString());
	}

	public Collection<AnchorDefinition> getAllAnchorDefinitions() {
		return anchorManager.getAnchorsByHelpPath().values();
	}

	public Path getFile() {
		return helpFile;
	}

	@Override
	public String toString() {
		return helpFile.toUri().toString();
	}

//==================================================================================================
// Parsing Methods    
//==================================================================================================

	private void parseLinks() {
		ReferenceTagProcessor tagProcessor = new ReferenceTagProcessor(help, anchorManager);
		processHelpFile(helpFile, anchorManager, tagProcessor);

		if (tagProcessor.getErrorCount() > 0) {
			String errorText = tagProcessor.getErrorText();
			throw new AssertException(
				"Errors parsing HTML file: " + helpFile.getFileName() + "\n" + errorText);
		}
	}

	private static void processHelpFile(Path file, AnchorManager anchorManager,
			TagProcessor tagProcessor) {

		String fname = file.getFileName().toString().toLowerCase();
		if (fname.endsWith(".htm") || fname.endsWith(".html")) {
			try {
				anchorManager.addAnchor(file, null, -1);
				HTMLFileParser.scanHtmlFile(file, tagProcessor);
			}
			catch (IOException e) {
				System.err.println("Exception parsing file: " + file.toUri() + "\n");
				System.err.println(e.getMessage());
				e.printStackTrace();
			}
		}
		else {
			// We've already filtered for .htm, .html, no?
			throw new RuntimeException("Internal error");
		}
	}
}
