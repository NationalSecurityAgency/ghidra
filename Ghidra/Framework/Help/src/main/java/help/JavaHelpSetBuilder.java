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
package help;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class JavaHelpSetBuilder {
	private static final String TAB = "\t";
	private static final Set<String> searchFileNames =
		new HashSet<String>(Arrays.asList(new String[] { "DOCS", "DOCS.TAB", "OFFSETS",
			"POSITIONS", "SCHEMA", "TMAP" }));
	private static int indentionLevel;

	private final String moduleName;
	private final Path mapFile;
	private final Path tocFile;
	private final Path searchDirectory;
	private final Path helpSetFile;

	public JavaHelpSetBuilder(String moduleName, Path helpMapFile, Path helpTOCFile,
			Path indexerOutputDirectory, Path helpSetFile2) {
		this.moduleName = moduleName;
		this.mapFile = helpMapFile;
		this.tocFile = helpTOCFile;
		this.searchDirectory = indexerOutputDirectory;
		this.helpSetFile = helpSetFile2;
	}

	public void writeHelpSetFile() throws IOException {
		BufferedWriter writer = null;
		try {
			OutputStreamWriter osw = new OutputStreamWriter(Files.newOutputStream(helpSetFile));
			writer = new BufferedWriter(osw);

			generateFileHeader(writer, moduleName);

			writeMapEntry(mapFile, writer);

			writeTOCEntry(tocFile, writer);

			writeSearchEntry(searchDirectory, writer);

			writeFavoritesEntry(writer);

			generateFileFooter(writer);
		}
		finally {
			if (writer != null) {
				try {
					writer.close();
				}
				catch (IOException e) {
					// we tried
				}
			}
		}
	}

	private static void writeMapEntry(Path helpSetMapFile, BufferedWriter writer)
			throws IOException {
		writeLine("<maps>", writer);

		indentionLevel++;
		writeLine("<mapref location=\"" + helpSetMapFile.getFileName() + "\" />", writer);
		indentionLevel--;

		writeLine("</maps>", writer);
	}

	private static void writeTOCEntry(Path helpSetTOCFile, BufferedWriter writer)
			throws IOException {
		writeLine("<view mergetype=\"javax.help.UniteAppendMerge\">", writer);

		indentionLevel++;
		writeLine("<name>TOC</name>", writer);
		writeLine("<label>Ghidra Table of Contents</label>", writer);
		writeLine("<type>docking.help.CustomTOCView</type>", writer);
		writeLine("<data>" + helpSetTOCFile.getFileName() + "</data>", writer);
		indentionLevel--;

		writeLine("</view>", writer);
	}

	private static void writeSearchEntry(Path helpSearchDirectory, BufferedWriter writer)
			throws IOException {
		if (!Files.exists(helpSearchDirectory)) {
			return; // some help dirs don't have content, like GhidraHelp
		}

		writeLine("<view>", writer);

		indentionLevel++;
		writeLine("<name>Search</name>", writer);
		writeLine("<label>Search for Keywords</label>", writer);
//		writeLine("<type>javax.help.SearchView</type>", writer);
		writeLine("<type>docking.help.CustomSearchView</type>", writer);

		if (hasIndexerFiles(helpSearchDirectory)) {
			writeLine("<data engine=\"com.sun.java.help.search.DefaultSearchEngine\">" +
				helpSearchDirectory.getFileName() + "</data>", writer);
		}
		indentionLevel--;

		writeLine("</view>", writer);
	}

	private static boolean hasIndexerFiles(Path helpSearchDirectory) {
		Set<String> found = new HashSet<String>();
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(helpSearchDirectory);) {
			for (Path file : ds) {
				found.add(file.getFileName().toString());
			}
		}
		catch (IOException e) {
			// It doesn't exist, so it's "empty".
		}
		return searchFileNames.equals(found);
	}

	private static void writeFavoritesEntry(BufferedWriter writer) throws IOException {
		writeLine("<view>", writer);

		indentionLevel++;
		writeLine("<name>Favorites</name>", writer);
//        writeLine( "<label>Favorites</label>", writer );
//        writeLine( "<type>javax.help.FavoritesView</type>", writer );
		writeLine("<label>Ghidra Favorites</label>", writer);
		writeLine("<type>docking.help.CustomFavoritesView</type>", writer);
		indentionLevel--;

		writeLine("</view>", writer);
	}

	private static void generateFileHeader(BufferedWriter writer, String moduleName)
			throws IOException {
		writer.write("<?xml version='1.0' encoding='ISO-8859-1' ?>");
		writer.newLine();
		writer.write("<!DOCTYPE helpset PUBLIC \"-//Sun Microsystems Inc.//DTD JavaHelp "
			+ "HelpSet Version 2.0//EN\" \"http://java.sun.com/products/javahelp/helpset_2_0.dtd\">");
		writer.newLine();
		writer.newLine();

		writer.write("<!-- HelpSet auto-generated on " + (new Date()).toString() + " -->");
		writer.newLine();

		writer.write("<helpset version=\"2.0\">");
		writer.newLine();

		indentionLevel++;
		writeIndentation(writer);
		writer.write("<title>" + moduleName + " HelpSet</title>");
		writer.newLine();
	}

	private static void generateFileFooter(BufferedWriter writer) throws IOException {
		indentionLevel--;
		writer.write("</helpset>");
		writer.newLine();
	}

	private static void writeLine(String text, BufferedWriter writer) throws IOException {
		writeIndentation(writer);
		writer.write(text);
		writer.newLine();
	}

	private static void writeIndentation(BufferedWriter writer) throws IOException {
		for (int i = 0; i < indentionLevel; i++) {
			writer.write(TAB);
		}
	}
}
