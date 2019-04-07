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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.xml.sax.*;

import ghidra.xml.*;
import help.validator.LinkDatabase;

public class GhidraTOCFile {

	private static final String TOC_ITEM_ID = "id";
	private static final String TOC_ITEM_TEXT = "text";
	private static final String TOC_ITEM_TARGET = "target";
	private static final String TOC_ITEM_SORT_PREFERENCE = "sortgroup";

	public static final String TOC_ITEM_REFERENCE = "tocref";
	public static final String TOC_ITEM_DEFINITION = "tocdef";
	private static final String ROOT_ATTRIBUTE_NAME = "tocroot";

	private Map<String, TOCItemDefinition> mapOfIDsToTOCDefinitions = new HashMap<>();
	private List<TOCItemReference> listOfTOCReferences = new ArrayList<>();

	public static GhidraTOCFile createGhidraTOCFile(Path sourceTOCFile)
			throws IOException, SAXException {
		GhidraTOCFile ghidraTOCFile = parseTOCFile(sourceTOCFile);
		ghidraTOCFile.sourceTOCFile = sourceTOCFile;
		return ghidraTOCFile;
	}

	private Path sourceTOCFile;
	private DummyRootTOCItem rootItem;

	GhidraTOCFile(Path sourceFile) {
		sourceTOCFile = sourceFile;
	}

	private static GhidraTOCFile parseTOCFile(Path sourceTOCFile) throws SAXException, IOException {
		ErrorHandler handler = new ErrorHandler() {
			@Override
			public void warning(SAXParseException exception) throws SAXException {
				throw exception;
			}

			@Override
			public void error(SAXParseException exception) throws SAXException {
				throw exception;
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				throw exception;
			}
		};
		XmlPullParser parser = new NonThreadedXmlPullParserImpl(Files.newInputStream(sourceTOCFile),
			sourceTOCFile.toUri().toString(), handler, false);

		XmlElement root = parser.start();

		if (!ROOT_ATTRIBUTE_NAME.equals(root.getName())) {
			throw new IOException("TOC source file does not start with a root tag named \"" +
				ROOT_ATTRIBUTE_NAME + "\"");
		}

		GhidraTOCFile file = new GhidraTOCFile(sourceTOCFile);
		DummyRootTOCItem rootItem = new DummyRootTOCItem(sourceTOCFile);

		buildRootNodes(parser, file, rootItem);
		file.rootItem = rootItem;
		return file;
	}

	private static List<TOCItem> buildRootNodes(XmlPullParser parser, GhidraTOCFile file,
			TOCItem parent) {

		List<TOCItem> list = new ArrayList<>();

		while (parser.peek().isStart()) {
			XmlElement element = parser.next();
			TOCItem item = createTOCItem(element, parent, file);

			list.addAll(buildRootNodes(parser, file, item));

			parser.end(element);
			list.add(item);
		}

		return list;
	}

	private static TOCItem createTOCItem(XmlElement element, TOCItem parentItem,
			GhidraTOCFile file) {
		String typeOfTOCItem = element.getName();
		String ID = element.getAttribute(TOC_ITEM_ID);
		String text = element.getAttribute(TOC_ITEM_TEXT);
		String target = element.getAttribute(TOC_ITEM_TARGET);

		if (ID == null) {
			throw new IllegalArgumentException(
				"TOC \"" + typeOfTOCItem + "\" attribute \"" + TOC_ITEM_ID + "\" cannot be null!");
		}

		int lineNumber = element.getLineNumber();

		if (TOC_ITEM_REFERENCE.equals(typeOfTOCItem)) {
			return file.addTOCItemReference(
				new TOCItemReference(parentItem, file.sourceTOCFile, ID, lineNumber));
		}
		else if (TOC_ITEM_DEFINITION.equals(typeOfTOCItem)) {
			String sortPreference = element.getAttribute(TOC_ITEM_SORT_PREFERENCE);
			return file.addTOCItemDefinition(new TOCItemDefinition(parentItem, file.sourceTOCFile,
				ID, text, target, sortPreference, lineNumber));
		}

		throw new IllegalArgumentException("Unknown TOC type: " + typeOfTOCItem);
	}

	private TOCItemDefinition addTOCItemDefinition(TOCItemDefinition definition) {
		TOCItemDefinition previous =
			mapOfIDsToTOCDefinitions.put(definition.getIDAttribute(), definition);
		if (previous != null) {
			throw new IllegalArgumentException(
				"Cannot define the same TOC definition more than once!\n\tOld value:\n\t" +
					previous + "\n\tNew value:\n\t" + definition + "\n\n");
		}
		return definition;
	}

	private TOCItemReference addTOCItemReference(TOCItemReference reference) {
		listOfTOCReferences.add(reference);
		return reference;
	}

	public Map<String, TOCItemDefinition> getTOCDefinitionByIDMapping() {
		return new HashMap<>(mapOfIDsToTOCDefinitions);
	}

	Collection<TOCItemReference> getTOCReferences() {
		return new ArrayList<>(listOfTOCReferences);
	}

	public Collection<TOCItemDefinition> getTOCDefinitions() {
		return new ArrayList<>(mapOfIDsToTOCDefinitions.values());
	}

	public Collection<TOCItem> getAllTOCItems() {
		ArrayList<TOCItem> list = new ArrayList<>(listOfTOCReferences);
		list.addAll(mapOfIDsToTOCDefinitions.values());
		return list;
	}

	public Path getFile() {
		return sourceTOCFile;
	}

//==================================================================================================
//  Inner Classes
//==================================================================================================	

	static class DummyRootTOCItem extends TOCItem {

		DummyRootTOCItem(Path sourceFile) {
			super(null, sourceFile, "Dummy Root Item", "Dummy Root Item", null, null, -1);
		}

		@Override
		public String getIDAttribute() {
			return null;
		}

		void setChildren(List<TOCItem> rootChildren) {
			for (TOCItem item : rootChildren) {
				addChild(item);
			}
		}

		@Override
		protected void addChild(TOCItem child) {
			super.addChild(child);
		}

		@Override
		public boolean validate(LinkDatabase linkDatabase) {
			return true;
		}

		@Override
		public String toString() {
			return "Dummy Root:\n" + printChildren();
		}
	}
}
