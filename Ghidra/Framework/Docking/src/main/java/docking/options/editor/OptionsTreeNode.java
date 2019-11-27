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
package docking.options.editor;

import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeLazyNode;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.options.Options;
import resources.ResourceManager;

class OptionsTreeNode extends GTreeLazyNode {
	private final static Icon OPEN_FOLDER_ICON =
		ResourceManager.loadImage("images/openSmallFolder.png");
	private final static Icon CLOSED_FOLDER_ICON =
		ResourceManager.loadImage("images/closedSmallFolder.png");
	private final static Icon PROPERTIES_ICON =
		ResourceManager.loadImage("images/document-properties.png");

	private final Options options;
	private final String name;

	OptionsTreeNode(String name, Options options) {
		this.name = name;
		this.options = options;
	}

	OptionsTreeNode(Options options) {
		this(options.getName(), options);
	}

	@Override
	protected List<GTreeNode> generateChildren() {
		List<GTreeNode> childList = new ArrayList<GTreeNode>();
		if (options.getOptionsEditor() == null) { // if hasOptionsEditor, don't show child options	
			List<Options> childOptionsList = options.getChildOptions();
			for (Options childOptions : childOptionsList) {
				childList.add(new OptionsTreeNode(childOptions));
			}
		}
		Collections.sort(childList);
		return childList;
	}

//	/**
//	 * This method will get the last name in a delimited string. For example, if given
//	 * <tt>a.b.c.</tt>, then this method will return <tt>c</tt>.  As another example, if given 
//	 * <tt>a.</tt>, then this method will return <tt>a</tt> 
//	 */
//	static String getLastNameInPrefix( String prefixString ) {
//		// assume the delimiter is on the end of the string--chop it off!
//		// ex: a.b.c., where the last '.' we do not want
//		int length = prefixString.length();
//		String substring = prefixString.substring(0, length-1);
//		
//		// find the last delimiter in the remaining prefix, as we want the name after that
//		// ex: a.b.c, where the '.' after 'b' is what we are looking for
//		int lastDelimiterIndex = substring.lastIndexOf( EditableOptions.DELIMITER );
//		if ( lastDelimiterIndex < 0 ) {
//			return substring;  // no more delimiters in the string, so we want the string itself
//		}
//		
//		// the name is all text from the last delimiter
//		// ex: a.b.c, where the last delimiter is at index 3, substring from 4 to the end, or "c"
//		length = substring.length();
//		return substring.substring(lastDelimiterIndex+1, length);
//	}

	@Override
	public boolean isLeaf() {
		return getChildCount() == 0;
	}

	@Override
	public Icon getIcon(boolean isExpanded) {
		if (isLeaf()) {
			return PROPERTIES_ICON;
		}
		return isExpanded ? OPEN_FOLDER_ICON : CLOSED_FOLDER_ICON;
	}

	public int compareTo(OptionsTreeNode other) {
		return getName().compareTo(other.getName());
	}

	public String getGroupPathName() {
		return null;
	}

	public Options getOptions() {
		return options;
	}

	public List<String> getOptionNames() {
		if (options == null) {
			return new ArrayList<String>();
		}
		return options.getLeafOptionNames();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public int compareTo(GTreeNode other) {
		return getName().compareTo(other.getName());
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (obj.getClass() != getClass()) {
			return false;
		}
		return getName().equals(((OptionsTreeNode) obj).getName());
	}
}
