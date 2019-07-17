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
package help.validator;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import help.HelpBuildUtils;
import help.validator.location.HelpModuleLocation;
import help.validator.model.IMG;
import util.CollectionUtils;

public class UnusedHelpImageFileFinder {

	private static final String HELP_PATHS_OPTION = "-hp"; // taken from GHelpBuilder
	private static final String DEBUG_SWITCH = "-debug";

	private static List<String> moduleHelpPaths = new ArrayList<>();
	private static boolean debugEnabled = false;

	private SortedSet<Path> unusedFiles;

	public static void main(String[] args) {
		parseArguments(args);

		List<HelpModuleLocation> helpCollections = collectHelp();

		Collection<IMG> referencedIMGs = getReferencedIMGs(helpCollections);
		debug("Found " + referencedIMGs.size() + " image referenes from help files");

		Collection<Path> allImagesOnDisk = getAllImagesOnDisk(helpCollections);
		debug("Found " + allImagesOnDisk.size() + " image files in help directories");

		Collection<Path> unusedFiles = getUnusedFiles(referencedIMGs, allImagesOnDisk);
		if (unusedFiles.size() == 0) {
			System.out.println("No unused image files found!");
			System.exit(0);
		}

		System.err.println("Found the following " + unusedFiles.size() + " unused images: ");
		for (Path file : unusedFiles) {
			System.err.println(file.toUri());
		}
	}

	public UnusedHelpImageFileFinder(Collection<HelpModuleLocation> helpCollections) {
		this(helpCollections, debugEnabled);
	}

	public UnusedHelpImageFileFinder(Collection<HelpModuleLocation> helpCollections,
			boolean debugEnabled) {
		UnusedHelpImageFileFinder.debugEnabled = debugEnabled;

		Collection<IMG> referencedIMGs = getReferencedIMGs(helpCollections);
		debug("Found " + referencedIMGs.size() + " image referenes from help files");

		Collection<Path> allImagesOnDisk = getAllImagesOnDisk(helpCollections);
		debug("Found " + allImagesOnDisk.size() + " image files in help directories");

		unusedFiles = getUnusedFiles(referencedIMGs, allImagesOnDisk);
		debug("Found " + unusedFiles.size() + " unused images");
	}

	public SortedSet<Path> getUnusedImages() {
		return new TreeSet<>(unusedFiles);
	}

	private static SortedSet<Path> getUnusedFiles(Collection<IMG> referencedIMGs,
			Collection<Path> imageFiles) {

		Map<Path, IMG> fileToIMGMap = new HashMap<>();
		for (IMG img : referencedIMGs) {
			fileToIMGMap.put(img.getImageFile(), img);
		}

		SortedSet<Path> set =
			new TreeSet<>((f1, f2) -> f1.toUri().toString().toLowerCase().compareTo(
				f2.toUri().toString().toLowerCase()));
		for (Path file : imageFiles) {
			IMG img = fileToIMGMap.get(file);
			if (img == null && !isExcludedImageFile(file)) {
				set.add(file);
			}
		}
		return set;
	}

	private static boolean isExcludedImageFile(Path file) {
		String absolutePath = file.toUri().toString().toLowerCase();
		// Could be done by subpath examination
		return absolutePath.indexOf("help/shared/") != -1;
	}

	private static Collection<IMG> getReferencedIMGs(
			Collection<HelpModuleLocation> helpCollections) {
		Set<IMG> set = new HashSet<>();
		for (HelpModuleLocation help : helpCollections) {
			Collection<IMG> IMGs = help.getAllIMGs();
			set.addAll(IMGs);
		}
		return set;
	}

	private static Collection<Path> getAllImagesOnDisk(
			Collection<HelpModuleLocation> helpDirectories) {
		List<Path> files = new ArrayList<>();
		for (HelpModuleLocation help : helpDirectories) {
			Path helpDir = help.getHelpLocation();
			gatherImageFiles(helpDir, files);
		}
		return files;
	}

	private static void gatherImageFiles(Path file, final List<Path> files) {
		try {
			Files.walkFileTree(file, new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult visitFile(Path path, BasicFileAttributes attrs)
						throws IOException {
					if (isImageFile(path)) {
						files.add(path);
					}
					return FileVisitResult.CONTINUE;
				}
			});
		}
		catch (IOException e) {
			// Must not exist
		}
	}

	private static boolean isImageFile(Path file) {
		String filename = file.getFileName().toString().toLowerCase();
		return filename.endsWith(".png") || filename.endsWith(".gif") || filename.endsWith(".jpg");
	}

	private static List<HelpModuleLocation> collectHelp() {
		debug("Parsing help dirs...");
		List<HelpModuleLocation> helpCollections = new ArrayList<>(moduleHelpPaths.size());
		for (String helpDirName : moduleHelpPaths) {

			// Make sure the help directory exists
			File helpDirectoryFile = null;
			try {
				helpDirectoryFile = new File(helpDirName).getCanonicalFile();
				debug("\tadding help dir: " + helpDirectoryFile);
			}
			catch (IOException e) {
				// handled below
			}

			if (helpDirectoryFile == null || !helpDirectoryFile.isDirectory()) {
				errorMessage("Help directory not found - skipping: " + helpDirName);
				continue;
			}

			// Create the help directory
			helpCollections.add(HelpBuildUtils.toLocation(helpDirectoryFile));
		}

		return helpCollections;
	}

	private static void debug(String string) {
		if (debugEnabled) {
			System.out.println(
				"[" + UnusedHelpImageFileFinder.class.getSimpleName() + "] " + string);
		}
	}

	private static void printUsage() {
		StringBuilder buffy = new StringBuilder();

		errorMessage("Usage:\n");
		buffy.append("-hp path1[-hp path2 -hp path3 ...]> [-debug]");

		errorMessage(buffy.toString());
	}

	private static void parseArguments(String[] args) {
		if (args.length == 0) {
			errorMessage("Missing required arguments - must supply at least one module help path");
			printUsage();
			System.exit(1);
		}

		List<String> argList = CollectionUtils.asList(args);
		int debugIndex = argList.indexOf(DEBUG_SWITCH);
		if (debugIndex > -1) {
			debugEnabled = true;
			argList.remove(debugIndex);
		}

		Map<Integer, String> mapped = new TreeMap<>();
		for (int i = 0; i < argList.size(); i++) {
			mapped.put(i, argList.get(i));
		}

		for (int i = 0; i < argList.size(); i++) {
			String opt = argList.get(i);
			if (opt.equals(HELP_PATHS_OPTION)) {

				if (i >= argList.size()) {
					errorMessage(HELP_PATHS_OPTION + " requires an argument");
					printUsage();
					System.exit(1);
				}

				mapped.remove(i);
				String paths = mapped.remove(++i);
				if (StringUtils.isBlank(paths)) {
					errorMessage(HELP_PATHS_OPTION + " requires an argument");
					printUsage();
					System.exit(1);
				}

				// each entry should be just one value, but handle multiple paths anyway
				for (String p : paths.split(File.pathSeparator)) {
					moduleHelpPaths.add(p);
				}
			}
		}

		if (moduleHelpPaths.size() == 0) {
			errorMessage(
				"Missing molule help path(s) arguments - actual arguments:\n\t'" + argList + "'");
			printUsage();
			System.exit(1);
		}

		if (!mapped.isEmpty()) {
			errorMessage("Ignoring unknown arguments: " + mapped.values());
		}
	}

	private static void errorMessage(String message) {
		errorMessage(message, null);
	}

	private static void errorMessage(String message, Throwable t) {
		System.err.println("[" + UnusedHelpImageFileFinder.class.getSimpleName() + "] " + message);
		if (t != null) {
			t.printStackTrace();
		}
	}
}
