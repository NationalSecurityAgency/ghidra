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
package ghidra.app.plugin.core.datamgr.tree;

import javax.swing.Icon;

import ghidra.app.plugin.core.datamgr.archive.BuiltInArchive;
import ghidra.util.HTMLUtilities;
import resources.MultiIcon;

public class BuiltInArchiveNode extends ArchiveNode {

	public BuiltInArchiveNode(BuiltInArchive archive, ArrayPointerFilterState filterState) {
		super(archive, filterState);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		Icon baseIcon = archive.getIcon(expanded);
		MultiIcon multiIcon = new MultiIcon(baseIcon);
		return multiIcon;
	}

	@Override
	public String getToolTip() {
		StringBuilder buf = new StringBuilder(HTMLUtilities.HTML);
		buf.append("Built In Data Types");
		buf.append(HTMLUtilities.BR);
		buf.append(HTMLUtilities.HTML_SPACE);
		buf.append(HTMLUtilities.HTML_SPACE);
		buf.append(DEFAULT_DATA_ORG_DESCRIPTION);
		return buf.toString();
	}

}
