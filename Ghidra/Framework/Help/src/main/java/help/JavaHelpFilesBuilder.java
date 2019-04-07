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
package help;

import ghidra.util.exception.AssertException;
import help.validator.LinkDatabase;
import help.validator.location.HelpModuleCollection;
import help.validator.model.AnchorDefinition;
import help.validator.model.GhidraTOCFile;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * This class:
 * <ul>
 *      <li>Creates a XXX_map.xml file (topic IDs to help files)</li>
 *      <li>Creates a XXX_TOC.xml file from a source toc.xml file</li>
 *      <li>Finds unused images</li>
 * </ul>
 */
public class JavaHelpFilesBuilder {
	private static final String MAP_OUTPUT_FILENAME_SUFFIX = "_map.xml";
	private static final String TOC_OUTPUT_FILENAME_SUFFIX = "_TOC.xml";

	private static final String LOG_FILENAME = "help.log";

	private final String moduleName;
	private Path outputDir;
	private String mapOutputFilename;
	private String tocOutputFilename;
	private LinkDatabase linkDatabase;

	public JavaHelpFilesBuilder(Path outputDir, String moduleName, LinkDatabase linkDatabase) {
		this.moduleName = moduleName;
		this.linkDatabase = linkDatabase;
		this.outputDir = initializeOutputDirectory(outputDir);

		mapOutputFilename = moduleName + MAP_OUTPUT_FILENAME_SUFFIX;
		tocOutputFilename = moduleName + TOC_OUTPUT_FILENAME_SUFFIX;
	}

	private Path initializeOutputDirectory(Path outputDirectory) {
		if (!Files.exists(outputDirectory)) {
			try {
				return Files.createDirectories(outputDirectory);
			}
			catch (IOException e) {
				return null;
			}
		}
		return outputDirectory;
	}

	public void generateHelpFiles(HelpModuleCollection help) throws Exception {
		message("Generating Help Files for: " + help);

		LogFileWriter errorLog = createLogFile();

		boolean hasErrors = false;
		StringBuffer shortErrorDescription = new StringBuffer();
		try {
			generateMapFile(help);
		}
		catch (IOException e) {
			hasErrors = true;
			shortErrorDescription.append("Unexpected error generating map file!\n");
			errorLog.append("Failed to generate " + mapOutputFilename + ": ");
			errorLog.append(e.getMessage());
			errorLog.println();
		}

		try {
			generateTOCFile(linkDatabase, help);
		}
		catch (IOException e) {
			hasErrors = true;
			shortErrorDescription.append("Unexpected error writing TOC file!\n");
			errorLog.append("Failed to generate " + tocOutputFilename + ": ");
			errorLog.append(e.getMessage());
			errorLog.println();
		}

		if (hasErrors) {
			errorLog.close();
			throw new RuntimeException("Errors Creating Help Files - " + shortErrorDescription +
				"\n\tsee help log for details: " + errorLog.getFile());
		}

		errorLog.close();
		if (errorLog.isEmpty()) {
			errorLog.delete();
		}

		message("Done generating help files for module: " + moduleName);
	}

	private LogFileWriter createLogFile() throws IOException {
		String logFilename = moduleName + "." + LOG_FILENAME;
		Path logFile = outputDir.resolve(logFilename);
		return new LogFileWriter(logFile);
	}

	private static void message(String message) {
		System.out.println("[" + JavaHelpFilesBuilder.class.getSimpleName() + "] " + message);
		System.out.flush();
	}

	private void generateMapFile(HelpModuleCollection help) throws IOException {
		Path mapFile = outputDir.resolve(mapOutputFilename);
		message("Generating map file: " + mapFile.toUri() + "...");
		if (Files.exists(mapFile)) {
			Files.delete(mapFile);
		}
		PrintWriter out = new LogFileWriter(mapFile);
		try {
			out.println("<?xml version='1.0' encoding='ISO-8859-1' ?>");
			out.println("<!doctype MAP public \"-//Sun Microsystems Inc.//DTD JavaHelp Map Version 1.0//EN\">");
			out.println("<!-- Auto-generated on " + (new Date()).toString() + " : Do Not Edit -->");
			out.println("<map version=\"1.0\">");

			Collection<AnchorDefinition> anchors = help.getAllAnchorDefinitions();
			Iterator<AnchorDefinition> iterator = anchors.iterator();
			while (iterator.hasNext()) {
				AnchorDefinition a = iterator.next();
				String anchorTarget = a.getHelpPath();

				//
				// JavaHelp Note:  the JavaHelp system will resolve relative map entries by using
				//                 this map file that we are generating as the base. So, whatever
				//                 directory this file lives under is the root directory for the
				//                 relative path that we are writing here for the 'mapID' entry.
				//                 Thus, make sure that the relative entry is relative to the 
				//                 directory of this map file.
				//

				String updatedPath = relativize(outputDir, anchorTarget);
				out.println("  <mapID target=\"" + a.getId() + "\" url=\"" + updatedPath + "\"/>");
			}
			out.println("</map>");
			message("\tfinished generating map file");
		}
		finally {
			out.close();
		}
	}

	private String relativize(Path parent, String anchorTarget) {
		Path anchorPath = Paths.get(anchorTarget);
		if (anchorPath.isAbsolute()) {
			return anchorTarget; // not a relative path; nothing to do
		}

		if (!parent.endsWith("help")) {
			throw new AssertException("Map file expected in a directory name 'help'.  "
				+ "Update the map file generation code.");
		}

		if (!anchorTarget.startsWith("help")) {
			throw new AssertException("Relative anchor path does not start with 'help'");
		}

		Path relative = anchorPath.subpath(1, anchorPath.getNameCount());
		String relativePath = relative.toString();
		String normalized = relativePath.replaceAll("\\\\", "/");
		return normalized;
	}

	private void generateTOCFile(LinkDatabase database, HelpModuleCollection help)
			throws IOException {
		message("Generating TOC file: " + tocOutputFilename + "...");
		GhidraTOCFile sourceTOCFile = help.getSourceTOCFile();
		Path outputFile = outputDir.resolve(tocOutputFilename);
		database.generateTOCOutputFile(outputFile, sourceTOCFile);
		message("\tfinished generating TOC file");
	}

//==================================================================================================
// Inner Classes
//==================================================================================================    

	private class LogFileWriter extends PrintWriter {
		private final Path file;

		LogFileWriter(Path logFile) throws IOException {
			super(new BufferedWriter(new OutputStreamWriter(Files.newOutputStream(logFile))));
			this.file = logFile;
		}

		Path getFile() {
			return file;
		}

		boolean isEmpty() {
			try {
				return Files.size(file) == 0;
			}
			catch (IOException e) {
				return true;
			}
		}

		void delete() {
			try {
				Files.delete(file);
			}
			catch (IOException e) {
			}
		}
	}
}
