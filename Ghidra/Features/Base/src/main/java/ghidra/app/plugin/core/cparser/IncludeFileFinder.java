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
package ghidra.app.plugin.core.cparser;

import ghidra.graph.*;
import ghidra.graph.jung.JungDirectedGraph;

import java.io.File;
import java.io.IOException;
import java.util.*;

import utilities.util.FileUtilities;

public class IncludeFileFinder {

	private File rootDir;
	private int rootPathPrefixLength;

	public IncludeFileFinder(File rootDir) {
		this.rootDir = rootDir;
		rootPathPrefixLength = rootDir.getAbsolutePath().length() + 1;
	}

	public List<String> getIncludeFiles(boolean recursive) {
		List<IncludeFile> includeFileList = findIncludeFiles(recursive);
		return getPaths(includeFileList);
	}

	public List<String> getIncludeFileRoots(boolean recursive) throws IOException {
		List<IncludeFile> includeFileList = findIncludeFiles(recursive);

		GDirectedGraph<IncludeFile, GEdge<IncludeFile>> g =
			new JungDirectedGraph<IncludeFile, GEdge<IncludeFile>>();

		processIncludeFiles(includeFileList, g);
		Set<IncludeFile> roots = GraphAlgorithms.getEntryPoints(g);
		List<String> paths = getPaths(roots);
		Collections.sort(paths);
		return paths;
	}

	private static void processIncludeFiles(List<IncludeFile> fileSet,
			GDirectedGraph<IncludeFile, GEdge<IncludeFile>> g) throws IOException {
		for (IncludeFile includeFile : fileSet) {
			List<String> lines = FileUtilities.getLines(includeFile.file);
			for (String line : lines) {
				if (line.toLowerCase().contains("include")) {
					processLine(includeFile, fileSet, line, g);
				}
			}
		}
	}

	private static void processLine(IncludeFile fromFile, List<IncludeFile> fileSet, String line,
			GDirectedGraph<IncludeFile, GEdge<IncludeFile>> g) {
		for (IncludeFile referencedFile : fileSet) {
			String relativePath = referencedFile.getRelativePath();
			if (line.contains(relativePath)) {
				g.addEdge(new DefaultGEdge<IncludeFile>(fromFile, referencedFile));
			}
		}
	}

	private List<String> getPaths(Collection<IncludeFile> includeFileList) {
		List<String> list = new ArrayList<String>(includeFileList.size());
		for (IncludeFile includeFile : includeFileList) {
			list.add(includeFile.relativePath);
		}
		return list;
	}

	private List<IncludeFile> findIncludeFiles(boolean recursive) {
		List<IncludeFile> fileList = new ArrayList<IncludeFile>();
		doFindIncludeFiles(rootDir, fileList, recursive);
		return fileList;
	}

	private void doFindIncludeFiles(File dir, List<IncludeFile> fileList, boolean recursive) {
		if (!dir.isDirectory()) {
			return;
		}
		File[] listFiles = dir.listFiles();
		for (File file : listFiles) {
			if (isInclude(file)) {
				fileList.add(new IncludeFile(file));
			}
			else if (recursive) {
				doFindIncludeFiles(file, fileList, recursive);
			}
		}
	}

	private boolean isInclude(File file) {
		if (file.getName().endsWith(".h")) {
			return true;
		}
		return false;
	}

	class IncludeFile {
		private File file;
		private String relativePath;

		IncludeFile(File file) {
			this.file = file;
			this.relativePath = file.getAbsolutePath().substring(rootPathPrefixLength);
		}

		public String getRelativePath() {
			return relativePath;
		}

		public File getFile() {
			return file;
		}
	}

	public static void main(String[] args) throws IOException {
		File root =
			new File(
				"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/usr/include");
		IncludeFileFinder finder = new IncludeFileFinder(root);
		List<String> roots = finder.getIncludeFileRoots(true);

		for (String string : roots) {
			System.out.println(string);
		}
		System.out.println("root list size = " + roots.size());
	}
}
