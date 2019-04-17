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
package ghidra.app.util.bin.format.pe.rich;

import java.io.*;
import java.util.*;

import org.apache.commons.io.FilenameUtils;
import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.xml.*;

class RichProductIdLoader {

	public static Map<Integer, RichProduct> loadProductIdStore() {

		List<ResourceFile> fileList = new ArrayList<>();

		try {
			ResourceFile builtIn = Application.getModuleDataFile("ms_pe_rich_products.xml");

			if (builtIn != null) {
				fileList.add(builtIn);
			}

			File userFile = Application.getUserSettingsDirectory().getParentFile();
			String userFilePath =
				userFile.getAbsolutePath().concat(File.separator).concat("rich_ids.xml");

			ResourceFile user = new ResourceFile(new File(userFilePath));

			if (user.exists()) {
				fileList.add(user);
			}
		}
		catch (FileNotFoundException fnfe) {
			// ignored;
		}

		Map<Integer, RichProduct> store = new HashMap<>();
		for (ResourceFile file : fileList) {
			if (file.exists()) {
				try {
					loadFile(file, store);
				}
				catch (IOException ioe) {
					Msg.error(RichProductIdLoader.class, "Error loading " + file.getName(), ioe);
				}
			}
		}
		return store;
	}

	private static MSProductType resolveProductType(String toolDescription) {
		String descr = toolDescription.toLowerCase();

		if (descr.contains("import") || toolDescription.equals("IMP")) {
			return MSProductType.Import;
		}
		if (descr.contains("export") || toolDescription.equals("EXP")) {
			return MSProductType.Export;
		}
		if (descr.contains("imp/exp")) {
			return MSProductType.ImportExport;
		}
		if (descr.contains("linker")) {
			return MSProductType.Linker;
		}
		if (toolDescription.contains("link ") || toolDescription.equals("LNK")) {
			return MSProductType.Linker;
		}
		if (descr.contains("masm") || toolDescription.equals("ASM")) {
			return MSProductType.Assembler;
		}
		if (descr.contains("cvtres") || toolDescription.equals("RES")) {
			return MSProductType.CVTRes;
		}
		if (descr.contains("c++ compiler")) {
			return MSProductType.CXX_Compiler;
		}
		if (descr.contains("c compiler")) {
			return MSProductType.C_Compiler;
		}

		if (toolDescription.equals("C++")) {
			return MSProductType.CXX_Compiler;
		}
		if (toolDescription.equals("C")) {
			return MSProductType.C_Compiler;
		}

		return MSProductType.Unknown;
	}

	private static void loadFile(ResourceFile file, Map<Integer, RichProduct> store)
			throws FileNotFoundException, IOException {

		String fileExtension = FilenameUtils.getExtension(file.getAbsolutePath()).toLowerCase();
		if (fileExtension.equals("xml")) {
			try {
				loadXMLFile(file, store);
			}
			catch (XmlParseException xpe) {
				throw new IOException("Error loading XML file: " + xpe.getMessage(), xpe);
			}
		}
	}

	private static void loadXMLFile(ResourceFile file, Map<Integer, RichProduct> store)
			throws FileNotFoundException, IOException, XmlParseException {

		InputStream stream = file.getInputStream();
		String name = file.getName();

		loadXMLFile(name, stream, store);

		stream.close();

	}

	private static void loadXMLFile(String name, InputStream stream,
			Map<Integer, RichProduct> store) throws IOException, XmlParseException {

		XmlPullParser parser;
		try {
			parser = new NonThreadedXmlPullParserImpl(stream, name, new XMLErrorHandler(), false);
		}
		catch (SAXException e) {
			throw new XmlParseException("Sax Exception", e);
		}
		parser.next();// skip root element start
		try {
			processProducts(parser, store);
		}
		catch (SAXParseException spe) {
			Msg.error(RichProductIdLoader.class, "Error occurred while parsing XML file " + name,
				spe);
		}
	}

	private static void processProducts(XmlPullParser parser, Map<Integer, RichProduct> store)
			throws SAXParseException {
		XmlElement element = parser.next();
		while (!element.isEnd()) {
			String name = element.getName();
			if (name.equals("product")) {
				RichProduct product = loadRichProduct(element);
				if (product != null) {
					store.put(product.getCompid().getValue(), product);
				}
			}
			else {
				throw new SAXParseException("Unexpected element: " + name, null, null,
					parser.getLineNumber(), parser.getColumnNumber());
			}
			element = parser.next();// read end tag
			element = parser.next();// advance to next start
		}
	}

	private static RichProduct loadRichProduct(XmlElement element) {

		String prodidStr = element.getAttribute("prodid");
		String tool = element.getAttribute("tool");
		String name = element.getAttribute("name");

		int id = Integer.parseInt(prodidStr, 16);

		MSProductType type = resolveProductType(tool);

		return new RichProduct(id, name, type);

	}

	private static class XMLErrorHandler implements ErrorHandler {
		@Override
		public void error(SAXParseException exception) throws SAXException {
			throw new SAXException("Error: " + exception);
		}

		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			throw new SAXException("Fatal error: " + exception);
		}

		@Override
		public void warning(SAXParseException exception) throws SAXException {
			throw new SAXException("Warning: " + exception);
		}
	}

}
