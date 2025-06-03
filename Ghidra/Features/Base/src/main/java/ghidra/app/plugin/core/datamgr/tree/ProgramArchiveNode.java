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

import ghidra.app.plugin.core.datamgr.archive.ProgramArchive;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.HTMLUtilities;

public class ProgramArchiveNode extends DomainFileArchiveNode {

	public ProgramArchiveNode(ProgramArchive archive, DtFilterState filterState) {
		super(archive, filterState);
	}

	@Override
	public String getToolTip() {
		DataTypeManager dtm = archive.getDataTypeManager();
		DomainFile file = ((ProgramArchive) archive).getDomainFile();
		StringBuilder buf = new StringBuilder(HTMLUtilities.HTML);
		if (file != null) {
			buf.append(HTMLUtilities.escapeHTML(file.toString()));
		}
		else {
			buf.append("[Unsaved New Program Archive]");
		}
		buf.append(HTMLUtilities.BR);
		buf.append(HTMLUtilities.HTML_SPACE);
		buf.append(HTMLUtilities.HTML_SPACE);
		buf.append(HTMLUtilities.escapeHTML(dtm.getProgramArchitectureSummary()));
		return buf.toString();
	}
}
