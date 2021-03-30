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
package ghidra.app.util.xml;

import org.xml.sax.SAXParseException;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlAttributes;
import ghidra.util.xml.XmlWriter;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class BookmarksXmlMgr {
	private BookmarkManager bookmarkMgr;
	private AddressFactory factory;
	private MessageLog log;

	BookmarksXmlMgr(Program program, MessageLog log) {
		this.bookmarkMgr = program.getBookmarkManager();
		this.factory = program.getAddressFactory();
		this.log = log;
	}

	///////////////////////////////////////////////////////////////////////////////////////
	//                            XML READ CURRENT DTD                                   //
	///////////////////////////////////////////////////////////////////////////////////////

	void read(XmlPullParser parser, boolean overwrite, TaskMonitor monitor)
			throws SAXParseException, AddressFormatException, CancelledException {

		XmlElement element = parser.next();
		if (!element.isStart() || !element.getName().equals("BOOKMARKS")) {
			throw new SAXParseException("Expected BOOKMARKS start tag", null, null,
				parser.getLineNumber(), parser.getColumnNumber());
		}

		element = parser.next();
		while (element.getName().equals("BOOKMARK")) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			processBookmark(element, parser, overwrite);
			element = parser.next();
		}

		if (element.isStart() || !element.getName().equals("BOOKMARKS")) {
			throw new SAXParseException("Expected BOOKMARK element or BOOKMARKS end tag", null,
				null, parser.getLineNumber(), parser.getColumnNumber());
		}
	}

	private void processBookmark(XmlElement element, XmlPullParser parser, boolean overwrite)
			throws SAXParseException, AddressFormatException {

		String addrStr = element.getAttribute("ADDRESS");
		if (addrStr == null) {
			throw new SAXParseException("ADDRESS attribute missing for BOOKMARK element", null,
				null, parser.getLineNumber(), parser.getColumnNumber());
		}
		Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
		if (addr == null) {
			throw new AddressFormatException("Incompatible Bookmark Address: " + addrStr);
		}

		String type = element.getAttribute("TYPE");
		if (type == null) {
			type = BookmarkType.NOTE;
		}

		String category = element.getAttribute("CATEGORY");
		if (category == null) {
			category = "";
		}

		String comment = element.getAttribute("DESCRIPTION");
		if (comment == null) {
			comment = "";
		}

		try {
			boolean hasExistingBookmark = bookmarkMgr.getBookmark(addr, type, category) != null;
			if (overwrite || !hasExistingBookmark) {
				bookmarkMgr.setBookmark(addr, type, category, comment);
			}
			if (!overwrite && hasExistingBookmark) {
				log.appendMsg("Conflicting '" + type + "' BOOKMARK ignored at: " + addr);
			}
		}
		catch (Exception e) {
			log.appendException(e);
			parser.discardSubTree(element);
			return;
		}

		element = parser.next();
		if (element.isStart() || !element.getName().equals("BOOKMARK")) {
			throw new SAXParseException("Expected BOOKMARK end tag", null, null,
				parser.getLineNumber(), parser.getColumnNumber());
		}
	}

	///////////////////////////////////////////////////////////////////////////////////////
	//   						 XML WRITE CURRENT DTD                                   //
	///////////////////////////////////////////////////////////////////////////////////////

	void write(XmlWriter writer, AddressSetView set, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Writing BOOKMARKS ...");
		writer.startElement("BOOKMARKS");
		writeBookmarks(writer, set, monitor);
		writer.endElement("BOOKMARKS");
	}

	/**
	 * @param writer
	 */
	private void writeBookmarks(XmlWriter writer, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {

		BookmarkType[] types = bookmarkMgr.getBookmarkTypes();
		for (int i = 0; i < types.length; i++) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			String typeStr = types[i].getTypeString();
			AddressSetView bmSet = bookmarkMgr.getBookmarkAddresses(typeStr);
			if (set != null) {
				bmSet = set.intersect(bmSet);
			}
			AddressIterator iter = bmSet.getAddresses(true);
			while (iter.hasNext()) {
				Address addr = iter.next();
				Bookmark[] bookmarks = bookmarkMgr.getBookmarks(addr, typeStr);
				for (int n = 0; n < bookmarks.length; n++) {
					if (monitor.isCancelled()) {
						return;
					}
					XmlAttributes attrs = new XmlAttributes();
					attrs.addAttribute("ADDRESS", XmlProgramUtilities.toString(addr));
					attrs.addAttribute("TYPE", typeStr);
					String category = bookmarks[n].getCategory();
					String comment = bookmarks[n].getComment();
					if (category != null && category.length() != 0) {
						attrs.addAttribute("CATEGORY", category);
					}
					if (comment != null && comment.length() != 0) {
						attrs.addAttribute("DESCRIPTION", comment);
					}
					writer.startElement("BOOKMARK", attrs);
					writer.endElement("BOOKMARK");
				}
			}
		}
	}
}
