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

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

import javax.help.HelpSet;

import ghidra.util.exception.AssertException;
import help.validator.model.*;

public abstract class HelpModuleLocation {

	/** The help dir parent of the help topics and such */
	protected Path helpDir;

	private List<HelpTopic> helpTopics = new ArrayList<>();

	/** this is the TOC_Source.xml file, not the generated file */
	protected GhidraTOCFile sourceTOCFile;
	private HelpSet helpSet;

	HelpModuleLocation(Path source) {
		this.helpDir = source;

		loadHelpTopics();
		sourceTOCFile = loadSourceTOCFile();
		helpSet = loadHelpSet();
	}

	public abstract GhidraTOCFile loadSourceTOCFile();

	public abstract HelpSet loadHelpSet();

	/** Returns true if this help location represents a source of input files to generate help output */
	public abstract boolean isHelpInputSource();

	protected void loadHelpTopics() {
		Path helpTopicsDir = helpDir.resolve("topics");
		if (!Files.exists(helpTopicsDir)) {
			throw new AssertException("No topics found in help dir: " + helpDir);
		}

		try (DirectoryStream<Path> ds = Files.newDirectoryStream(helpTopicsDir);) {
			for (Path file : ds) {
				if (Files.isDirectory(file)) {
					helpTopics.add(new HelpTopic(this, file));
				}
			}
		}
		catch (IOException e) {
			// I suppose there aren't any
			throw new AssertException("No topics found in help dir: " + helpDir);
		}
	}

	public Path getHelpLocation() {
		return helpDir;
	}

	public Path getHelpModuleLocation() {
		// format: <module>/src/main/help/help/topics/<topic name>/<topic file>
		// help dir: <module>/src/main/help/help/

		Path srcMainHelp = helpDir.getParent();
		Path srcMain = srcMainHelp.getParent();
		Path src = srcMain.getParent();
		Path module = src.getParent();
		return module;
	}

	public Path getModuleRepoRoot() {

		// module path format: <git dir>/<repo root>/<repo>/Features/Foo
		Path module = getHelpModuleLocation();
		Path category = module.getParent();
		Path repo = category.getParent();
		Path repoRoot = repo.getParent();
		return repoRoot;
	}

	GhidraTOCFile getSourceTOCFile() {
		return sourceTOCFile;
	}

	HelpSet getHelpSet() {
		return helpSet;
	}

	public Collection<HelpTopic> getHelpTopics() {
		return new ArrayList<>(helpTopics);
	}

	public Collection<HREF> getAllHREFs() {
		List<HREF> list = new ArrayList<>();
		for (HelpTopic helpTopic : helpTopics) {
			list.addAll(helpTopic.getAllHREFs());
		}
		return list;
	}

	public Collection<IMG> getAllIMGs() {
		List<IMG> list = new ArrayList<>();
		for (HelpTopic helpTopic : helpTopics) {
			list.addAll(helpTopic.getAllIMGs());
		}
		return list;
	}

	Collection<AnchorDefinition> getAllAnchorDefinitions() {
		List<AnchorDefinition> list = new ArrayList<>();
		for (HelpTopic helpTopic : helpTopics) {
			list.addAll(helpTopic.getAllAnchorDefinitions());
		}
		return list;
	}

	Collection<HelpFile> getHelpFiles() {
		List<HelpFile> result = new ArrayList<>();
		for (HelpTopic topic : helpTopics) {
			result.addAll(topic.getHelpFiles());
		}
		return result;
	}

	boolean containsHelp() {
		if (helpTopics.isEmpty()) {
			return false;
		}

		for (HelpTopic topic : helpTopics) {
			Collection<HelpFile> helpFiles = topic.getHelpFiles();
			if (!helpFiles.isEmpty()) {
				return true;
			}
		}

		return false;
	}

	Map<HelpFile, Map<String, List<AnchorDefinition>>> getDuplicateAnchorsByFile() {
		Map<HelpFile, Map<String, List<AnchorDefinition>>> map = new HashMap<>();
		for (HelpTopic helpTopic : helpTopics) {
			Collection<HelpFile> helpFiles = helpTopic.getHelpFiles();
			for (HelpFile helpFile : helpFiles) {
				Map<String, List<AnchorDefinition>> anchors = helpFile.getDuplicateAnchorsByID();
				if (anchors.size() > 0) {
					map.put(helpFile, anchors);
				}
			}
		}
		return map;
	}

	Map<HelpTopic, List<AnchorDefinition>> getDuplicateAnchorsByTopic() {
		Map<HelpTopic, List<AnchorDefinition>> map = new HashMap<>();
		for (HelpTopic helpTopic : helpTopics) {
			List<AnchorDefinition> duplicateDefinitions =
				getDuplicateTopicAnchorDefinitions(helpTopic);
			if (duplicateDefinitions.size() > 0) {
				map.put(helpTopic, duplicateDefinitions);
			}
		}
		return map;
	}

	private List<AnchorDefinition> getDuplicateTopicAnchorDefinitions(HelpTopic helpTopic) {
		Map<String, List<AnchorDefinition>> map = new HashMap<>();
		Collection<HelpFile> helpFiles = helpTopic.getHelpFiles();

		// collect all the anchor definitions by name
		for (HelpFile helpFile : helpFiles) {
			Collection<AnchorDefinition> definitions = helpFile.getAllAnchorDefinitions();
			for (AnchorDefinition anchorDefinition : definitions) {
				String name = anchorDefinition.getAnchorName();
				if (name == null) {
					continue; // ignore anchor definitions, as they don't exist in the source code
				}
				List<AnchorDefinition> list = map.get(name);
				if (list == null) {
					list = new ArrayList<AnchorDefinition>();
					map.put(name, list);
				}
				list.add(anchorDefinition);
			}
		}

		// add the contents of all the lists with more than one item
		List<AnchorDefinition> list = new ArrayList<>();
		Collection<List<AnchorDefinition>> values = map.values();
		for (List<AnchorDefinition> definitions : values) {
			if (definitions.size() > 1) {
				list.addAll(definitions);
			}
		}
		return list;
	}

	@Override
	public String toString() {
		return helpDir.toUri().toString();
	}
}
