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
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

import help.GHelpMsg;
import help.HelpBuildUtils;
import help.validator.location.DirectoryHelpModuleLocation;
import help.validator.location.HelpModuleLocation;

public class HelpTopic implements Comparable<HelpTopic> {
	private final HelpModuleLocation help;
	private final Path topicDir;

	// topics/TopicName
	private final Path relativePath;

	private Map<Path, HelpFile> helpFiles;

	public static HelpTopic fromHTMLFile(Path topicFile) {

		// format: <module>/src/main/help/help/topics/<topic name>/<topic file>

		Path topic = topicFile.getParent();
		Path topicsDir = topic.getParent();
		Path helpDir = topicsDir.getParent();

		DirectoryHelpModuleLocation loc = new DirectoryHelpModuleLocation(helpDir.toFile());
		HelpTopic helpTopic = new HelpTopic(loc, topicFile);
		return helpTopic;
	}

	public HelpTopic(HelpModuleLocation help, Path topicDir) {
		this.help = help;
		this.topicDir = topicDir;

		Path helpDir = help.getHelpLocation();

		// topic file: /help/topics/TopicName
		// relative:   topics/TopicName
		Path relativeTopicPath = helpDir.relativize(topicDir); // may or may not be jar paths
		this.relativePath = HelpBuildUtils.relativeToWorkingDir(relativeTopicPath);
	}

	public Path getTopicDir() {
		return topicDir;
	}

	private void lazyLoad() {
		if (helpFiles != null) {
			return;
		}

		helpFiles = new LinkedHashMap<>();
		loadHelpFiles(topicDir);
	}

	private void loadHelpFiles(Path dir) {
		FileSystem fs = dir.getFileSystem();
		PathMatcher matcher =
			fs.getPathMatcher("glob:**/*.{[Hh][Tt][Mm],[Hh][Tt][Mm][Ll]}");

		// Ex: /help/topics/FooPlugin
		Path dirDefaultFS = HelpBuildUtils.relativeToWorkingDir(dir);
		try {
			Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
						throws IOException {
					if (matcher.matches(file)) {
						mapHelpFile(dirDefaultFS, file);
					}
					return FileVisitResult.CONTINUE;
				}
			});
		}
		catch (IOException e) {
			GHelpMsg.error("Error loading help files: " + dir.toUri(), e);
		}
	}

	private void mapHelpFile(Path dirDefaultFS, Path file) {

		// Ex:  /help/topics/FooPlugin/Foo.html
		Path fileDefaultFS = HelpBuildUtils.relativeToWorkingDir(file);

		// Ex:  Foo.html
		Path relFilePath = dirDefaultFS.relativize(fileDefaultFS);

		// Ex:  topics/FooPlugin/Foo.html
		relFilePath = relativePath.resolve(relFilePath);
		helpFiles.put(relFilePath, new HelpFile(help, file));
	}

	void addHelpFile(Path relPath, HelpFile helpFile) {
		lazyLoad();
		helpFiles.put(relPath, helpFile);
	}

	public Collection<HREF> getAllHREFs() {
		// Don't need to validate hrefs already in a .jar
		if (topicDir.getFileSystem() != FileSystems.getDefault()) {
			return Collections.emptyList();
		}

		lazyLoad();
		List<HREF> list = new ArrayList<>();
		for (HelpFile helpFile : helpFiles.values()) {
			list.addAll(helpFile.getAllHREFs());
		}
		return list;
	}

	public Collection<IMG> getAllIMGs() {
		// Don't need to validate imgs already in a .jar
		if (topicDir.getFileSystem() != FileSystems.getDefault()) {
			return Collections.emptyList();
		}

		lazyLoad();
		List<IMG> list = new ArrayList<>();
		for (HelpFile helpFile : helpFiles.values()) {
			list.addAll(helpFile.getAllIMGs());
		}
		return list;
	}

	public Collection<AnchorDefinition> getAllAnchorDefinitions() {
		// The current module may refer to anchors in pre-built modules.
		lazyLoad();
		List<AnchorDefinition> list = new ArrayList<>();
		for (HelpFile helpFile : helpFiles.values()) {
			list.addAll(helpFile.getAllAnchorDefinitions());
		}
		return list;
	}

	public Collection<HelpFile> getHelpFiles() {
		lazyLoad();
		return helpFiles.values();
	}

	/**
	 * Returns the relative path, which is {@code topics/TopicName}
	 * @return the path
	 */
	Path getRelativePath() {
		return relativePath;
	}

	public HelpModuleLocation getHelpDirectory() {
		return help;
	}

	public String getName() {
		return topicDir.getFileName().toString();
	}

	@Override
	public int compareTo(HelpTopic o) {
		return topicDir.compareTo(o.topicDir);
	}

	@Override
	public String toString() {
		return topicDir.toString();
	}
}
