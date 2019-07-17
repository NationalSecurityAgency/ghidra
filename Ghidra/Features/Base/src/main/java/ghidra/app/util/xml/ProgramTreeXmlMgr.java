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

import ghidra.app.util.PluginConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.datastruct.Stack;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlAttributes;
import ghidra.util.xml.XmlWriter;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.io.IOException;
import java.util.ArrayList;

/**
 * XML manager for program trees.
 */
class ProgramTreeXmlMgr {
	private Listing listing;
	private MessageLog log;
	private AddressFactory factory;

	private ArrayList<String> fragmentNameList;
	private Stack<ProgramModule> moduleStack;
	private String treeName;
	private TaskMonitor monitor;

	/**
	 * Constructor
	 * @param program program
	 * @param log message log 
	 */
	ProgramTreeXmlMgr(Program program, MessageLog log) {
		this.log = log;
		listing = program.getListing();
		factory = program.getAddressFactory();
		moduleStack = new Stack<ProgramModule>();
	}

	/**
	 * Read the Program tree section from an XML file.
	 * @param parser parser for the XML
	 * @param monitor monitor that can be canceled
	 * @param addToProgram true if we are adding trees to an existing
	 * program
	 */
	void read(XmlPullParser parser, TaskMonitor m, boolean addToProgram) throws CancelledException {
		this.monitor = m;

		//remove the default tree that is created when a program
		//is instantiated...
		if (!addToProgram) {
			listing.removeTree(PluginConstants.DEFAULT_TREE_NAME);
		}

		XmlElement trees = parser.start("PROGRAM_TREES");
		while (parser.peek().isStart()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			XmlElement element = null;
			try {
				element = parser.next();
				processTree(element, parser);
			}
			catch (Exception e) {
				log.appendException(e);
				parser.discardSubTree(element);
			}
		}
		parser.end(trees);
	}

	/**
	 * Write out the XML for the program trees.
	 * @param writer writer for XML
	 * @param monitor monitor that can be canceled
	 * should be written
	 * @throws IOException
	 */
	void write(XmlWriter writer, AddressSetView addrs, TaskMonitor m) throws CancelledException {
		this.monitor = m;
		monitor.setMessage("Writing PROGRAM TREES ...");

		writer.startElement("PROGRAM_TREES");
		String[] treeNames = listing.getTreeNames();

		for (int i = 0; i < treeNames.length; i++) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("NAME", treeNames[i]);
			writer.startElement("TREE", attrs);

			ProgramModule root = listing.getRootModule(treeNames[i]);

			ArrayList<ProgramModule> writtenModules = new ArrayList<ProgramModule>();
			ArrayList<ProgramFragment> writtenFragments = new ArrayList<ProgramFragment>();

			writeModule(writer, addrs, root, writtenModules, writtenFragments);

			writer.endElement("TREE");
		}
		writer.endElement("PROGRAM_TREES");
	}

	private void processTree(XmlElement treeElement, XmlPullParser parser) {
		treeName = treeElement.getAttribute("NAME");
		fragmentNameList = new ArrayList<String>();

		ProgramModule root = null;
		try {
			try {
				root = listing.createRootModule(treeName);
			}
			catch (DuplicateNameException dne) {
				// if name already existed, then attempt to create a 
				// unique "one-up" name
				//
				int oneUp = 1;
				while (true) {
					try {
						root = listing.createRootModule(treeName + "(" + oneUp + ")");
						break; // we located a unique name...
					}
					catch (DuplicateNameException e) {
						++oneUp;
					}
				}
				treeName = root.getTreeName();
			}
			moduleStack.push(root);

			XmlElement element = parser.next();

			while (!monitor.isCancelled()) {
				String elementName = element.getName();
				if (elementName.equals("FRAGMENT") || elementName.equals("MODULE") ||
					elementName.equals("FOLDER")) {
					if (elementName.equals("FRAGMENT")) {
						if (element.isStart()) {
							processFragment(element, parser);
						}
					}
					else {
						if (element.isStart()) {
							processModule(element, parser);
						}
						else {
							moduleStack.pop();
						}
					}
					element = parser.next();
				}
				else {
					break;
				}
			}
			removeEmptyFragments(root);
		}
		catch (Exception e) {
			log.appendException(e);
			parser.discardSubTree(treeElement);
		}
	}

	private void processModule(XmlElement element, XmlPullParser parser) {
		String name = element.getAttribute("NAME");
		ProgramModule parent = moduleStack.peek();
		ProgramModule newModule = null;
		try {
			try {
				newModule = parent.createModule(name);
			}
			catch (DuplicateNameException dne) {
				newModule = listing.getModule(treeName, name);
				parent.add(newModule);
			}
			moduleStack.push(newModule);
		}
		catch (Exception e) {
			log.appendException(e);
			parser.discardSubTree(element);
		}
	}

	private void processFragment(XmlElement element, XmlPullParser parser) {

		String name = element.getAttribute("NAME");

		if (!fragmentNameList.contains(name)) {
			fragmentNameList.add(name);
		}
		ProgramModule parent = moduleStack.peek();
		ProgramFragment frag = null;
		try {
			frag = parent.createFragment(name);
		}
		catch (DuplicateNameException dne) {
			frag = listing.getFragment(treeName, name);
			try {
				parent.add(frag);
			}
			catch (DuplicateGroupException dge) {
				// ignore, we are trying to add a fragment to
				// a module that already contains it
			}
		}
		try {
			processFragmentRange(frag, parser);
		}
		catch (NotFoundException e) {
			log.appendMsg(e.getMessage());
			parser.discardSubTree(element);
		}
		catch (Exception e) {
			log.appendException(e);
			parser.discardSubTree(element);
		}
	}

	private void processFragmentRange(ProgramFragment frag, XmlPullParser parser)
			throws AddressFormatException, NotFoundException {

		XmlElement element = parser.next();

		while (!monitor.isCancelled()) {
			String elementName = element.getName();
			if (elementName.equals("ADDRESS_RANGE")) {
				if (element.isStart()) {
					String startStr = element.getAttribute("START");
					String endStr = element.getAttribute("END");

					Address start = XmlProgramUtilities.parseAddress(factory, startStr);
					Address end = XmlProgramUtilities.parseAddress(factory, endStr);

					if (start == null || end == null) {
						throw new AddressFormatException("Incompatible Fragment Address Range: [" +
							startStr + "," + endStr + "]");
					}

					frag.move(start, end);
				}
				element = parser.next();
			}
			else {
				return;
			}
		}

	}

	/**
	 * Method removeEmptyFragments.
	 */
	private void removeEmptyFragments(ProgramModule module) {
		Group[] groups = module.getChildren();
		for (int i = 0; i < groups.length; i++) {
			if (groups[i] instanceof ProgramFragment) {
				String name = groups[i].getName();
				if (!fragmentNameList.contains(name)) {
					try {
						module.removeChild(name);
					}
					catch (NotEmptyException e) {
						log.appendMsg("Warning: Extra Program Tree fragment '" + name +
							"' did not exist in imported XML file");
					}
				}
			}
			else {
				removeEmptyFragments((ProgramModule) groups[i]);
			}
		}
	}

	private void writeModule(XmlWriter writer, AddressSetView addrs, ProgramModule parent,
			ArrayList<ProgramModule> writtenModules, ArrayList<ProgramFragment> writtenFragments) {

		XmlAttributes attrs = new XmlAttributes();
		boolean writeTag = false;
		if (parent != listing.getRootModule(parent.getTreeName())) {
			writeTag = true;
			attrs.addAttribute("NAME", parent.getName());
			writer.startElement("FOLDER", attrs);
		}

		if (!writtenModules.contains(parent)) {
			writtenModules.add(parent);
			Group[] kids = parent.getChildren();
			for (int i = 0; i < kids.length; i++) {
				if (kids[i] instanceof ProgramModule) {
					writeModule(writer, addrs, (ProgramModule) kids[i], writtenModules, writtenFragments);
				}
				else {
					writeFragment(writer, addrs, (ProgramFragment) kids[i], writtenFragments);
				}
			}
		}
		if (writeTag) {
			writer.endElement("FOLDER");
		}
	}

	private void writeFragment(XmlWriter writer, AddressSetView addrs, ProgramFragment fragment,
			ArrayList<ProgramFragment> writtenFragments) {
		if (fragment == null) {
			return;
		}
		AddressSetView fragmentSet = addrs.intersect(fragment);
		if (fragmentSet.isEmpty()) {
			return;
		}
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("NAME", fragment.getName());
		writer.startElement("FRAGMENT", attrs);

		if (!writtenFragments.contains(fragment)) {
			writtenFragments.add(fragment);
			writeFragmentRange(writer, fragment, fragmentSet);
		}
		writer.endElement("FRAGMENT");
	}

	private void writeFragmentRange(XmlWriter writer, ProgramFragment fragment, AddressSetView fragmentSet) {

		AddressRangeIterator iter = fragmentSet.getAddressRanges();
		while (iter.hasNext()) {
			XmlAttributes attrs = new XmlAttributes();
			AddressRange range = iter.next();
			attrs.addAttribute("START", XmlProgramUtilities.toString(range.getMinAddress()));
			attrs.addAttribute("END", XmlProgramUtilities.toString(range.getMaxAddress()));
			writer.startElement("ADDRESS_RANGE", attrs);
			writer.endElement("ADDRESS_RANGE");
		}
	}
}
