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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import help.validator.LinkDatabase;
import help.validator.model.*;

/**
 * A class that will take in a group of help directories and create a tree of
 * help Table of Contents (TOC) items.  Ideally, this tree can be used to create a single
 * TOC document, or individual TOC documents, one for each help directory (this allows
 * for better modularity).
 * <p>
 * We call this class an <b>overlay</b> tree to drive home the idea that each
 * help directory's TOC data is put into the tree, with any duplicate paths overlayed
 * on top of those from other help directories.
 */
public class OverlayHelpTree {

	private Map<String, Set<TOCItem>> parentToChildrenMap = new HashMap<String, Set<TOCItem>>();
	private TOCItem rootItem;
	private OverlayNode rootNode;
	private final LinkDatabase linkDatabase;

	public OverlayHelpTree(TOCItemProvider tocItemProvider, LinkDatabase linkDatabase) {
		this.linkDatabase = linkDatabase;
		for (TOCItemExternal external : tocItemProvider.getExternalTocItemsById().values()) {
			addExternalTOCItem(external);
		}

		for (TOCItemDefinition definition : tocItemProvider.getTocDefinitionsByID().values()) {
			addSourceTOCItem(definition);
		}
	}

	private void addExternalTOCItem(TOCItem item) {
		TOCItem parent = item.getParent();
		String parentID = parent == null ? null : parent.getIDAttribute();
		if (parentID == null) {
			// must be the root, since the root has no parent
			if (rootItem != null) {

				//
				// We will have equivalent items in the generated TOC files, as that is how we
				// enable merging of TOC files in the JavaHelp system.  So, multiple roots are
				// OK.
				//

				if (!item.isEquivalent(rootItem)) {
					throw new IllegalArgumentException(
						"Cannot define more than one root node:\n\t" + item +
							", but there already exists\n\t" + rootItem);
				}
			}
			else {
				rootItem = item;
			}
			return;
		}

		doAddTOCIItem(item);
	}

	private void addSourceTOCItem(TOCItem item) {
		TOCItem parent = item.getParent();
		String parentID = parent == null ? null : parent.getIDAttribute();
		if (parentID == null) {
			// must be the root, since the root has no parent
			if (rootItem != null) {
				// when loading source items, it is only an error when there is more than one
				// root item defined *in the same file*
				if (rootItem.getSourceFile().equals(item.getSourceFile())) {
					throw new IllegalArgumentException(
						"Cannot define more than one root node in the same file:\n\t" + item +
							",\nbut there already exists\n\t" + rootItem);
				}
			}
			else {
				rootItem = item;
			}
			return;
		}

		doAddTOCIItem(item);
	}

	private void doAddTOCIItem(TOCItem item) {
		TOCItem parent = item.getParent();
		String parentID = parent == null ? null : parent.getIDAttribute();
		Set<TOCItem> set = parentToChildrenMap.get(parentID);
		if (set == null) {
			set = new LinkedHashSet<TOCItem>();
			parentToChildrenMap.put(parentID, set);
		}

		set.add(item);
	}

	public void printTreeForID(Path outputFile, String sourceFileID) throws IOException {

		if (Files.exists(outputFile)) {
			Files.delete(outputFile);
		}

		OutputStreamWriter osw = new OutputStreamWriter(Files.newOutputStream(outputFile));
		PrintWriter writer = new PrintWriter(new BufferedWriter(osw));
		printTreeForID(writer, sourceFileID);

		// debug
		// writer = new PrintWriter(System.err);
		// printTreeForID(writer, sourceFileID);
	}

	void printTreeForID(PrintWriter writer, String sourceFileID) {
		initializeTree();

		try {
			writer.println("<?xml version='1.0' encoding='ISO-8859-1' ?>");
			writer.println("<!-- Auto-generated on " + (new Date()).toString() + " -->");
			writer.println();
			writer.println("<toc version=\"2.0\">");

			printContents(sourceFileID, writer);

			writer.println("</toc>");
		}
		finally {
			writer.close();
		}
	}

	private void printContents(String sourceFileID, PrintWriter writer) {
		if (rootNode == null) {
			// assume not TOC contents; empty TOC file
			return;
		}

		rootNode.print(sourceFileID, writer, 0);
	}

	private boolean initializeTree() {
		if (rootNode != null) {
			return true;
		}

		if (rootItem == null) {
			// no content in the TOC file; help module does not appear in TOC view
			return false;
		}

		OverlayNode newRootNode = new OverlayNode(null, rootItem);
		buildChildren(newRootNode);

		//
		// The parent to children map is cleared as nodes are created.   The map is populated by
		// adding any references to the 'parent' key as they are loaded from the help files.
		// As we build nodes, starting at the root, will will create child nodes for those that
		// reference the 'parent' key.   If the map is empty, then it means we never built a
		// node for the 'parent' key, which means we never found a help file containing the
		// definition for that key.
		//
		if (!parentToChildrenMap.isEmpty()) {
			throw new RuntimeException("Unresolved definitions in tree! - " + parentToChildrenMap);
		}
		rootNode = newRootNode;
		return true;
	}

	private void buildChildren(OverlayNode node) {
		String definitionID = node.getDefinitionID();
		Set<TOCItem> children = parentToChildrenMap.remove(definitionID);
		if (children == null) {
			return; // childless
		}

		for (TOCItem child : children) {
			OverlayNode childNode = new OverlayNode(node, child);
			node.addChild(childNode);
			buildChildren(childNode);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class OverlayNode {
		private final TOCItem item;
		private final OverlayNode parentNode;
		private Set<String> fileIDs = new HashSet<String>();
		private Set<OverlayNode> children = new TreeSet<OverlayNode>(CHILD_SORT_COMPARATOR);

		public OverlayNode(OverlayNode parentNode, TOCItem rootItem) {
			this.parentNode = parentNode;
			this.item = rootItem;
			Path sourceFile = rootItem.getSourceFile();
			String fileID = sourceFile.toUri().toString();
			addFileIDToTreePath(fileID);
		}

		void print(String sourceFileID, PrintWriter writer, int indentLevel) {
			if (!fileIDs.contains(sourceFileID)) {
				return;
			}

			writer.println(item.generateTOCItemTag(linkDatabase, children.isEmpty(), indentLevel));
			if (!children.isEmpty()) {

				for (OverlayNode node : children) {
					node.print(sourceFileID, writer, indentLevel + 1);
				}
				writer.println(item.generateEndTag(indentLevel));
			}
		}

		void addChild(OverlayNode overlayNode) {
			children.add(overlayNode);
		}

		String getDefinitionID() {
			return item.getIDAttribute();
		}

		private void addFileIDToTreePath(String fileID) {
			fileIDs.add(fileID);
			if (parentNode != null) {
				parentNode.addFileIDToTreePath(fileID);
			}
		}

		TOCItem getTOCItemDefinition() {
			return item;
		}

		@Override
		public String toString() {
			return item.toString();
		}
	}

	// TODO LOOKIE
	private static final Comparator<OverlayNode> CHILD_SORT_COMPARATOR =
		new Comparator<OverlayNode>() {
			@Override
			public int compare(OverlayNode ov1, OverlayNode ov2) {
				TOCItem o1 = ov1.getTOCItemDefinition();
				TOCItem o2 = ov2.getTOCItemDefinition();

				if (!o1.getSortPreference().equals(o2.getSortPreference())) {
					return o1.getSortPreference().compareTo(o2.getSortPreference());
				}

				// if sort preference is the same, then sort alphabetically by display name
				String text1 = o1.getTextAttribute();
				String text2 = o2.getTextAttribute();

				// null values can happen for reference items
				if (text1 == null && text2 == null) {
					return 0;
				}

				// push any null values to the bottom
				if (text1 == null) {
					return 1;
				}
				else if (text2 == null) {
					return -1;
				}

				int result = text1.compareTo(text2);
				if (result != 0) {
					return result;
				}

				// At this point we have 2 nodes that have the same text attribute as children of
				// a <TOCDEF> tag.  This is OK, as we use text only for sorting, but not for the
				// display text.   Use the ID as a tie-breaker for sorting, which should provide
				// sorting consistency.
				return o1.getIDAttribute().compareTo(o2.getIDAttribute()); // ID should not be null
			}
		};
}
