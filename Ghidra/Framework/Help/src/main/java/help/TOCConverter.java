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

import java.io.*;
import java.util.*;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.ParserAdapter;

import ghidra.util.xml.XmlUtilities;

/**
 * Converts the Ghidra "source" TOC file to a JavaHelp TOC file. The Ghidra
 * source TOC file contains the table of context index name and its
 * corresponding url. However, JavaHelp expects the target value to be map ID in
 * the map file.
 * 
 */
public class TOCConverter {

	private String sourceFilename;
	private String outFilename;

	private final static String TOC_VERSION = "<toc version";
	private final static String TOCITEM = "<tocitem";
	private final static String TEXT = "text";
	private final static String TARGET = " target";

	private Map<String, String> urlMap; // map TOC target tag to its corresponding URL
	private List<String> tocList; // list of TOC entry names values

	TOCConverter(String sourceTOCfilename, String outFilename)
			throws IOException, SAXException, ParserConfigurationException {

		sourceFilename = sourceTOCfilename;
		this.outFilename = outFilename;
		urlMap = new HashMap<String, String>();
		tocList = new ArrayList<String>();
		readSourceTOC();
		writeJavaHelpTOC();
		System.out.println("  TOC conversion is done!");
	}

	/**
	 * Write the section of the map file for the table of contents.
	 * 
	 * @param out output for the map file that maps a help ID to a url.
	 * @throws IOException
	 */
	void writeTOCMapFile(PrintWriter out) {
		out.println("  <!-- Table of Contents help IDs -->");
		for (int i = 0; i < tocList.size(); i++) {
			String target = tocList.get(i);
			String url = urlMap.get(target);

			String line = "  <mapID target=\"" + target + "\" url=\"" + url + "\" />";
			out.println(line);
		}
		out.println("  <!-- End of Table of Contents help IDs -->");
	}

	/**
	 * Read the source table of contents file and build up hash maps to maintain
	 * TOC entry names to urls and map IDs.
	 */
	private void readSourceTOC() throws IOException, SAXException, ParserConfigurationException {
		SAXParserFactory factory = XmlUtilities.createSecureSAXParserFactory(false);
		XMLReader parser = new ParserAdapter(factory.newSAXParser().getParser());
		File file = createTempTOCFile();
		String fileURL = file.toURI().toURL().toString();
		TOCHandler handler = new TOCHandler();
		parser.setContentHandler(handler);
		parser.setErrorHandler(handler);
		parser.setFeature("http://xml.org/sax/features/namespaces", true);
		System.out.println("  Parsing input file " + sourceFilename);
		parser.parse(fileURL);
		file.deleteOnExit();
	}

	/**
	 * Write the JavaHelp table of contents file.
	 * 
	 * @throws IOException
	 */
	private void writeJavaHelpTOC() throws IOException {
		System.out.println("  Writing JavaHelp TOC file " + outFilename);
		PrintWriter out = new PrintWriter(new FileOutputStream(outFilename));
		BufferedReader reader = new BufferedReader(new FileReader(sourceFilename));

		String line = null;
		while ((line = reader.readLine()) != null) {
			if (line.indexOf(TOCITEM) > 0) {
				TOCItem item = parseLine(line);
				if (item == null) {
					continue;
				}
				String endline = " >";
				if (line.endsWith("/>")) {
					endline = " />";
				}
				line = getPadString(line) + TOCITEM + " " + TEXT + "=\"" + item.getText() + "\"";

				if (item.getTarget().length() > 0) {
					line = line + TARGET + "=\"" + item.getTarget() + "\"";
				}
				line = line + endline;
			}
			else if (line.indexOf(TOC_VERSION) == 0) {
				out.println("<!-- This is the JavaHelp Table of Contents file -->");
				out.println("<!-- Auto generated on " + new Date() + ": Do not edit! -->");
			}
			if (!line.startsWith("<!-- Source")) {
				out.println(line);
			}
		}

		out.close();
		reader.close();
	}

	private String getPadString(String line) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < line.length(); i++) {
			if (line.charAt(i) == ' ') {
				sb.append(' ');
			}
			else {
				break;
			}
		}
		return sb.toString();
	}

	private TOCItem parseLine(String line) {
		int pos = line.indexOf(TOCITEM);
		line = line.substring(pos + TOCITEM.length());
		StringTokenizer st = new StringTokenizer(line, "=\"");
		st.nextToken();
		String text = st.nextToken();
		if (st.hasMoreTokens()) {
			st.nextToken();
		}
		if (!st.hasMoreTokens()) {
			return new TOCItem(text, "");
		}
		String target = st.nextToken();
		return new TOCItem(text, target);
	}

	/**
	 * Creates a temporary TOC file that does not have the <!DOCTYPE line in it
	 * which causes the SAX parser to blow up; it does not like the bad url in
	 * it.
	 * 
	 * @return
	 * @throws IOException
	 */
	private File createTempTOCFile() throws IOException {
		File tempFile = File.createTempFile("toc", ".xml");

		PrintWriter out = new PrintWriter(new FileOutputStream(tempFile));
		BufferedReader reader = new BufferedReader(new FileReader(sourceFilename));
		boolean endLineFound = true;
		String line = null;
		while ((line = reader.readLine()) != null) {
			if (line.startsWith("<!DOCTYPE")) {
				if (line.endsWith(">")) {
					continue;
				}
				endLineFound = false;
			}
			if (!endLineFound) {
				if (line.endsWith(">")) {
					endLineFound = true;
					continue;
				}
			}
			out.println(line);
		}
		out.close();
		reader.close();
		return tempFile;
	}

	private class TOCItem {
		private String text;
		private String target;

		TOCItem(String text, String url) {
			this.text = text;
			target = url.replace('.', '_');
			target = target.replace('#', '_');
			target = target.replace('-', '_');
		}

		String getText() {
			return text;
		}

		String getTarget() {
			return target;
		}
	}

	private class TOCHandler extends DefaultHandler {

		/**
		 * @see org.xml.sax.ContentHandler#startElement(java.lang.String,
		 *      java.lang.String, java.lang.String, org.xml.sax.Attributes)
		 */
		@Override
		public void startElement(String namespaceURI, String localName, String qName,
				Attributes atts) throws SAXException {

			if (atts != null) {
				if (!atts.getQName(0).equals(TEXT)) {
					return;
				}

				String url = atts.getValue(1);
				String target = url;
				if (url != null && url.length() > 0) {
					target = target.replace('.', '_');
					target = target.replace('#', '_');
					target = target.replace('-', '_');

					urlMap.put(target, url);
					if (!tocList.contains(target)) {
						tocList.add(target);
					}
				}
			}
		}
	}

	public final static void main(String[] args) {
		if (args.length < 2) {
			System.out.println("Usage: TOCConverter [source TOC filename] [out filename]");
			System.exit(0);
		}

		try {
			TOCConverter conv = new TOCConverter(args[0], args[1]);
			File file = new File(args[1]);
			String name = file.getName();
			name = "map_" + name;

			PrintWriter out =
				new PrintWriter(new FileOutputStream(new File(file.getParentFile(), name)));
			conv.writeTOCMapFile(out);
			out.close();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

}
