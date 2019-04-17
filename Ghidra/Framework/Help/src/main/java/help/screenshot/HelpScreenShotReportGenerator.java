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
package help.screenshot;

import java.io.*;
import java.util.*;

public class HelpScreenShotReportGenerator {

	//
	// TODO sort and group the output by module
	//

	private static final int ITEMS_PER_PAGE = 25;
	private static final String PNG_EXT = ".png";

	public static void main(String[] args) throws Exception {

		if (args.length != 2) {
			throw new Exception(
				"Expecting 2 args: <output file path> <image filepath[,image filepath,...]>");
		}

		String filePath = args[0];
		System.out.println("Using file path: " + filePath);

		String images = args[1];
		if (images.trim().isEmpty()) {
			throw new Exception("No image files provided!");
		}

		System.out.println("Processing image files: " + images);

		StringTokenizer tokenizer = new StringTokenizer(images, ",");
		List<String> list = new ArrayList<String>();
		while (tokenizer.hasMoreTokens()) {
			list.add(tokenizer.nextToken());
		}

		HelpScreenShotReportGenerator generator = new HelpScreenShotReportGenerator();
		generator.generateReport(filePath, list);
	}

	private void generateReport(String filePath, List<String> list) throws Exception {

		int filenameStartIndex = filePath.lastIndexOf(File.separator) + 1;
		String parentPath = filePath.substring(0, filenameStartIndex);
		new File(parentPath).mkdirs(); // make sure the folder exists

		String baseFilename = filePath.substring(filenameStartIndex);

		//
		// Make a report that is a series of pages with a table of side-by-side images
		//
		int n = list.size();
		int pageCount = n / ITEMS_PER_PAGE;
		if (n % ITEMS_PER_PAGE != 0) {
			pageCount++;
		}

		String filenameNoExtension = baseFilename.substring(0, baseFilename.indexOf('.'));

		for (int i = 0; i < pageCount; i++) {

			BufferedWriter writer = null;
			try {
				String prefix = (i == 0) ? filenameNoExtension : filenameNoExtension + i;
				File file = new File(parentPath, prefix + ".html");
				System.out.println("Creating output file: " + file);

				writer = new BufferedWriter(new FileWriter(file));
				writeFile(filenameNoExtension, writer, i, pageCount, list);
			}
			catch (Exception e) {
				throw e;
			}
			finally {
				if (writer != null) {
					try {
						writer.close();
					}
					catch (IOException e) {
						// don't care
					}
				}
			}
		}
	}

	private void writeFile(String filenameNoExtension, BufferedWriter writer, int pageNumber,
			int pageCount, List<String> list) throws Exception {

		writeHeader(writer);
		writer.write("<P>\n");
		writer.write("<TABLE BORDER=\"1\">\n");

		int start = pageNumber * ITEMS_PER_PAGE;
		if (start > 0) {
			// 25 * 0 = 0
			// 25 * 1 = 25 => 26
			start++; // each page should start on the next item after the last end 
		}

		int n = Math.min(ITEMS_PER_PAGE, list.size() - start);
		int end = start + n;
		for (int i = start; i < end; i++) {

			String newFilePath = list.get(i);
			int originalExtention = newFilePath.indexOf(PNG_EXT);
			int length = originalExtention + PNG_EXT.length();
			String oldFilePath = newFilePath.substring(0, length);

			//@formatter:off
			writer.write("    <TR>\n");
			writer.write("        <TD>\n");
			writer.write("            <IMG SRC=\"" + oldFilePath + "\" ALT=\"" + oldFilePath + ".html\"><BR>\n");
			writer.write("            <CENTER><FONT COLOR=\"GRAY\">"+oldFilePath+"</FONT></CENTER>\n");
			writer.write("        </TD>\n");
			writer.write("        <TD>\n");
			writer.write("            <IMG SRC=\"" + newFilePath + "\" ALT=\"" + newFilePath + ".html\"><BR>\n");
			writer.write("            <CENTER><FONT COLOR=\"GRAY\">"+newFilePath+"</FONT></CENTER>\n");
			writer.write("        </TD>\n");
			writer.write("    </TR>\n");
			//@formatter:on
		}

		writer.write("</TABLE>\n");
		writer.write("</P>");

		writeFooter(filenameNoExtension, writer, pageCount);
	}

	private void writeHeader(BufferedWriter writer) throws IOException {
		writer.write("<HTML>\n");
		writer.write("<HEAD>\n");
		createStyleSheet(writer);
		writer.write("</HEAD>\n");
		writer.write("<BODY>\n");
		writer.write("<H1>\n");
		writer.write("Ghidra Help Screen Shots");
		writer.write("</H1>\n");
	}

	private void writeFooter(String filenameNoExtension, BufferedWriter writer, int pageCount)
			throws IOException {

		writer.write("<BR>\n");
		writer.write("<BR>\n");
		writer.write("<P>\n");
		writer.write("<CENTER>\n");

		for (int i = 0; i < pageCount; i++) {
			if (i == 0) {
				writer.write("<A HREF=\"" + filenameNoExtension + ".html\">" + (i + 1) + "</A>\n");
			}
			else {
				writer.write("<A HREF=\"" + filenameNoExtension + i + ".html\">" + (i + 1) +
					"</A>\n");
			}
		}

		writer.write("</CENTER>\n");
		writer.write("</P>\n");

		writer.write("</BODY>\n");
		writer.write("</HTML>\n");
	}

	private void createStyleSheet(BufferedWriter writer) throws IOException {
		writer.write("<style>\n");
		writer.write("<!--\n");

		writer.write("body { font-family:arial; font-size:22pt }\n");
		writer.write("h1 { color:#000080; font-family:times new roman; font-size:28pt; font-weight:bold; text-align:center; }\n");
		writer.write("h2 { color:#984c4c; font-family:times new roman; font-size:28pt; font-weight:bold; }\n");
		writer.write("h2.title { color:#000080; font-family:times new roman; font-size:14pt; font-weight:bold; text-align:center;}\n");
		writer.write("h3 { color:#0000ff; font-family:times new roman; font-size:14pt; font-weight:bold; margin-left:.5in }\n");
		writer.write("table { margin-left:1in; min-width:20em; width:95%; background-color:#EEEEFF }\n");
		writer.write("th { text-align:center;  }\n");
		writer.write("td { text-align:center; padding: 20px }\n");

		writer.write("-->\n");
		writer.write("</style>\n");
	}
}
