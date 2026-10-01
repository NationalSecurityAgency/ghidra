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

import generic.theme.GIcon;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.HTMLUtilities;

/**
 * Tree node representing datatypes from the currently active program
 */
public class ProgramArchiveNode extends DataTypeStoreNode implements VersionedNode {
	private static Icon CLOSED_ICON = new GIcon("icon.plugin.datatypes.archive.program.closed");
	private static Icon OPEN_ICON = new GIcon("icon.plugin.datatypes.archive.program.open");
	private VersionState versionState;

	public ProgramArchiveNode(Program program, DtFilterState filterState) {
		super(program, filterState);
		versionState = new VersionState(program);
	}

	public Program getProgram() {
		return (Program) dataTypeStore;
	}

	@Override
	public String getToolTip() {
		DomainFile file = getDomainObject().getDomainFile();
		DomainFile originalFile = file;
		if (file instanceof DomainFileProxy proxy) {
			originalFile = proxy.getOriginalDomainFile();
		}
		StringBuilder buf = new StringBuilder(HTMLUtilities.HTML);
		if (originalFile != null) {
			buf.append(HTMLUtilities.escapeHTML(originalFile.toString()));
		}
		else {
			buf.append("[Unsaved Program]");
		}
		buf.append(HTMLUtilities.BR);
		buf.append(HTMLUtilities.HTML_SPACE);
		buf.append(HTMLUtilities.HTML_SPACE);
		buf.append(HTMLUtilities.escapeHTML(dataTypeStore.getProgramArchitectureSummary()));
		return buf.toString();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		Icon baseIcon = expanded ? OPEN_ICON : CLOSED_ICON;
		return versionState.getIcon(baseIcon);
	}

	@Override
	public DomainObject getDomainObject() {
		return dataTypeStore;
	}

	@Override
	public String getDomainObjectInfo() {
		return versionState.getDomainObjectInfo();
	}

	@Override
	public void nodeChanged() {
		super.nodeChanged();
		versionState.updateDomainFileInfo();
	}

	@Override
	public DomainFile getOriginalDomainFile() {
		return versionState.getOriginalDomainFile();
	}

	@Override
	public DomainFile getDomainFile() {
		return dataTypeStore.getDomainFile();
	}
}
