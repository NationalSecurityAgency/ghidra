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

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.program.model.dtarchive.ArchiveWarning;
import ghidra.program.model.dtarchive.ArchiveWarning.ArchiveWarningLevel;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.util.HTMLUtilities;

/**
 * Nodes that represent a file or project datatype archive
 */
public class ArchiveNode extends DataTypeStoreNode {

	protected PersistentDataTypeArchive archive;

	protected ArchiveNode(PersistentDataTypeArchive archive, DtFilterState filterState) {
		super(archive, filterState);
		this.archive = archive;
	}

	public PersistentDataTypeArchive getArchive() {
		return archive;
	}

	protected String getArchitectureDetails() {

		StringBuilder buf = new StringBuilder();

		String programArchSummary = dataTypeStore.getProgramArchitectureSummary();
		if (programArchSummary != null) {
			buf.append(HTMLUtilities.HTML_SPACE);
			buf.append(HTMLUtilities.HTML_SPACE);
			buf.append(HTMLUtilities.escapeHTML(programArchSummary));
		}
		else {
			buf.append(DEFAULT_DATA_ORG_DESCRIPTION);
		}

		ArchiveWarning warning = archive.getWarning();
		if (warning != ArchiveWarning.NONE) {
			GColor c = Messages.NORMAL;
			ArchiveWarningLevel level = warning.level();
			if (level == ArchiveWarningLevel.ERROR) {
				c = Messages.ERROR;
			}
			else if (level == ArchiveWarningLevel.WARN) {
				c = Messages.WARNING;
			}
			String msg = archive.getWarningMessage(false);
			buf.append(HTMLUtilities.BR);
			buf.append("<font color=\"" + c + "\">** " + msg + " **</font>");
		}
		return buf.toString();
	}

}
