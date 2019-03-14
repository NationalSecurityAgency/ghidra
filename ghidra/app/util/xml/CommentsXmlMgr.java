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
package ghidra.app.util.xml;

import ghidra.app.util.CommentTypes;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlAttributes;
import ghidra.util.xml.XmlWriter;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.io.IOException;

/**
 * XML manager for all types of comments.
 */
class CommentsXmlMgr {
	private Program program;
	private MessageLog log;
	private AddressFactory factory;
	private Listing listing;

	private static int[] COMMENT_TYPES;
	private static String[] COMMENT_TAGS;

	static {
		COMMENT_TYPES = CommentTypes.getTypes();

		COMMENT_TAGS = new String[COMMENT_TYPES.length];
		for (int i = 0; i < COMMENT_TAGS.length; i++) {

			switch (COMMENT_TYPES[i]) {
				case CodeUnit.PRE_COMMENT:
					COMMENT_TAGS[i] = "pre";
					break;
				case CodeUnit.POST_COMMENT:
					COMMENT_TAGS[i] = "post";
					break;
				case CodeUnit.EOL_COMMENT:
					COMMENT_TAGS[i] = "end-of-line";
					break;
				case CodeUnit.PLATE_COMMENT:
					COMMENT_TAGS[i] = "plate";
					break;
				case CodeUnit.REPEATABLE_COMMENT:
					COMMENT_TAGS[i] = "repeatable";
					break;
			}
		}
	}

	CommentsXmlMgr(Program program, MessageLog log) {
		this.program = program;
		this.log = log;
		factory = program.getAddressFactory();
		listing = program.getListing();
	}

	/**
	 * Process the entry point section of the XML file.
	 * @param parser xml reader
	 * @param monitor monitor that can be canceled
	 */
	void read(XmlPullParser parser, TaskMonitor monitor) throws AddressFormatException,
			CancelledException {
		XmlElement element = parser.next();
		while (true) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			element = parser.next();
			if (!element.getName().equals("COMMENT")) {
				break;
			}
			if (element.isStart()) {
				processComment(element, parser);
			}
		}
	}

	/**
	 * Write out the XML for the external entry points.
	 * @param writer writer for XML
	 * @param set address set that is either the entire program or a selection
	 * @param monitor monitor that can be canceled
	 * should be written
	 * @throws IOException
	 */
	void write(XmlWriter writer, AddressSetView set, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Writing COMMENTS ...");

		if (set == null) {
			set = program.getMemory();
		}

		writer.startElement("COMMENTS");

		CodeUnitIterator iter = listing.getCodeUnitIterator(CodeUnit.COMMENT_PROPERTY, set, true);

		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			CodeUnit cu = iter.next();
			for (int i = 0; i < COMMENT_TYPES.length; i++) {
				if (monitor.isCancelled()) {
					return;
				}
				String comments = cu.getComment(COMMENT_TYPES[i]);
				if (comments != null) {
					writeComment(writer, cu.getMinAddress(), COMMENT_TAGS[i], comments);
				}
			}
		}
		writer.endElement("COMMENTS");
	}

	private void processComment(XmlElement element, XmlPullParser parser)
			throws AddressFormatException {
		String addrStr = element.getAttribute("ADDRESS");
		Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
		if (addr == null) {
			throw new AddressFormatException("Incompatible Comment Address: " + addrStr);
		}
		try {
			String typeStr = element.getAttribute("TYPE");
			int commentType = getCommentType(typeStr);
			if (commentType < 0) {
				log.appendMsg("Unknown comment type: " + typeStr);
				parser.discardSubTree(element);
				return;
			}
			element = parser.next();
			String comments = element.getText();

			CodeUnit cu = listing.getCodeUnitAt(addr);
			if (cu != null) {
				// if a comment already exists, then merge...
				//
				String currCmt = cu.getComment(commentType);
				if (currCmt == null || currCmt.length() == 0) {
					cu.setComment(commentType, comments);
				}
				else if (currCmt.indexOf(comments) < 0) {
					log.appendMsg("Merged " + typeStr + " comment at " + addr);
					cu.setComment(commentType, currCmt + "\n\n" + comments);
				}
			}
		}
		catch (Exception e) {
			log.appendException(e);
			parser.discardSubTree(element);
		}
	}

	private void writeComment(XmlWriter writer, Address addr, String typeStr, String comments) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("ADDRESS", XmlProgramUtilities.toString(addr));
		attrs.addAttribute("TYPE", typeStr);

		writer.writeElement("COMMENT", attrs, comments);
	}

	private int getCommentType(String typeStr) {
		for (int i = 0; i < COMMENT_TAGS.length; i++) {
			if (COMMENT_TAGS[i].equals(typeStr)) {
				return COMMENT_TYPES[i];
			}
		}
		return -1; // unknown comment 
	}
}
