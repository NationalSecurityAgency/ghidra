/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import help.HelpBuildUtils;
import help.validator.location.DirectoryHelpModuleLocation;
import help.validator.location.HelpModuleLocation;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

public class HelpTopic implements Comparable<HelpTopic> {
	private final HelpModuleLocation help;
	private final Path topicFile;
	private final Path relativePath;

	private Map<Path, HelpFile> helpFiles = new LinkedHashMap<Path, HelpFile>();

	public static HelpTopic fromHTMLFile(Path topicFile) {

		// format: <module>/src/main/help/help/topics/<topic name>/<topic file>

		Path topic = topicFile.getParent();
		Path topicsDir = topic.getParent();
		Path helpDir = topicsDir.getParent();

		DirectoryHelpModuleLocation loc = new DirectoryHelpModuleLocation(helpDir.toFile());
		HelpTopic helpTopic = new HelpTopic(loc, topicFile);
		return helpTopic;
	}

	public HelpTopic(HelpModuleLocation help, Path topicFile) {
		this.help = help;
		this.topicFile = topicFile;

		Path helpDir = help.getHelpLocation();

		Path unknowFSRelativePath = helpDir.relativize(topicFile); // may or may not be jar paths
		this.relativePath = HelpBuildUtils.toDefaultFS(unknowFSRelativePath);

		loadHelpFiles(topicFile);
	}

	public Path getTopicFile() {
		return topicFile;
	}

	private void loadHelpFiles(final Path dir) {
		final PathMatcher matcher =
			dir.getFileSystem().getPathMatcher("glob:**/*.{[Hh][Tt][Mm],[Hh][Tt][Mm][Ll]}");

		// Ex:
		// 		jar: /help/topics/FooPlugin
		final Path dirDefaultFS = HelpBuildUtils.toDefaultFS(dir);
		try {
			Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
						throws IOException {
					if (matcher.matches(file)) {
						// Ex:
						//		jar: /help/topics/FooPlugin/Foo.html
						Path fileDefaultFS = HelpBuildUtils.toDefaultFS(file);

						// Ex:  jar: Foo.html
						Path relFilePath = dirDefaultFS.relativize(fileDefaultFS);

						// Ex:  jar: topics/FooPlugin/Foo.html
						relFilePath = relativePath.resolve(relFilePath);
						helpFiles.put(relFilePath, new HelpFile(help, file));
					}
					return FileVisitResult.CONTINUE;
				}
			});
		}
		catch (IOException e) {
			System.err.println("Error loading help files: " + dir.toUri());
			e.printStackTrace(System.err);
		}
	}

	void addHelpFile(Path relPath, HelpFile helpFile) {
		helpFiles.put(relPath, helpFile);
	}

	public Collection<HREF> getAllHREFs() {
		// Don't need to validate hrefs already in a .jar
		if (topicFile.getFileSystem() != FileSystems.getDefault()) {
			return Collections.emptyList();
		}
		List<HREF> list = new ArrayList<HREF>();
		for (HelpFile helpFile : helpFiles.values()) {
			list.addAll(helpFile.getAllHREFs());
		}
		return list;
	}

	public Collection<IMG> getAllIMGs() {
		// Don't need to validate imgs already in a .jar
		if (topicFile.getFileSystem() != FileSystems.getDefault()) {
			return Collections.emptyList();
		}
		List<IMG> list = new ArrayList<IMG>();
		for (HelpFile helpFile : helpFiles.values()) {
			list.addAll(helpFile.getAllIMGs());
		}
		return list;
	}

	public Collection<AnchorDefinition> getAllAnchorDefinitions() {
		// The current module may refer to anchors in pre-built modules.
		List<AnchorDefinition> list = new ArrayList<AnchorDefinition>();
		for (HelpFile helpFile : helpFiles.values()) {
			list.addAll(helpFile.getAllAnchorDefinitions());
		}
		return list;
	}

	public Collection<HelpFile> getHelpFiles() {
		return helpFiles.values();
	}

	Path getRelativePath() {
		return relativePath;
	}

	public HelpModuleLocation getHelpDirectory() {
		return help;
	}

	public String getName() {
		return topicFile.getFileName().toString();
	}

	@Override
	public int compareTo(HelpTopic o) {
		return topicFile.compareTo(o.topicFile);
	}

	@Override
	public String toString() {
		return topicFile.toString();
	}
}
