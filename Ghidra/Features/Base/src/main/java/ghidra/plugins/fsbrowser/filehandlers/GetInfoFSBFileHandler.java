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
package ghidra.plugins.fsbrowser.filehandlers;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;
import static java.util.Map.*;

import java.awt.Component;
import java.io.IOException;
import java.util.*;
import java.util.function.Function;

import org.apache.commons.io.FilenameUtils;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.fileinfo.*;
import ghidra.framework.model.DomainFile;
import ghidra.plugins.fsbrowser.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GetInfoFSBFileHandler implements FSBFileHandler {

	public static final String FSB_GET_INFO = "FSB Get Info";
	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder(FSB_GET_INFO, context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getFSRL(true) != null)
				.popupMenuPath("Get Info")
				.popupMenuGroup("A", "A")
				.popupMenuIcon(FSBIcons.INFO)
				.description("Show information about a file")
				.onAction(ac -> {
					FSRL fsrl = ac.getFSRL(true);
					FSBComponentProvider fsbComp = ac.getComponentProvider();
					fsbComp.runTask(
						monitor -> showInfoForFile(ac.getSourceComponent(), fsrl, monitor));
				})
				.build());
	}

	private void showInfoForFile(Component parentComp, FSRL fsrl, TaskMonitor monitor) {
		if (fsrl == null) {
			Msg.showError(this, parentComp, "Missing File", "Unable to retrieve information");
			return;
		}

		// if looking at the root of a nested file system, also include its parent container
		List<FSRL> fsrls = (fsrl instanceof FSRLRoot && ((FSRLRoot) fsrl).hasContainer())
				? List.of(((FSRLRoot) fsrl).getContainer(), fsrl)
				: List.of(fsrl);
		String title = "Info about " + fsrls.get(0).getName();
		List<FileAttributes> fattrs = new ArrayList<>();
		for (FSRL fsrl2 : fsrls) {
			try {
				fattrs.add(getAttrsFor(fsrl2, monitor));
			}
			catch (IOException e) {
				Msg.warn(this, "Failed to get info for file " + fsrl2, e);
			}
			catch (CancelledException e) {
				return;
			}
		}
		String html = getHTMLInfoStringForAttributes(fattrs);

		MultiLineMessageDialog.showMessageDialog(parentComp, title, null, html,
			MultiLineMessageDialog.INFORMATION_MESSAGE);
	}

	private FileAttributes getAttrsFor(FSRL fsrl, TaskMonitor monitor)
			throws CancelledException, IOException {
		try (RefdFile refdFile = context.fsService().getRefdFile(fsrl, monitor)) {
			GFileSystem fs = refdFile.fsRef.getFilesystem();
			GFile file = refdFile.file;
			FileAttributes fattrs = fs.getFileAttributes(file, monitor);
			if (fattrs == null) {
				fattrs = FileAttributes.EMPTY;
			}
			fattrs = fattrs.clone();

			DomainFile associatedDomainFile = context.projectIndex().findFirstByFSRL(fsrl);
			if (associatedDomainFile != null) {
				fattrs.add(PROJECT_FILE_ATTR, associatedDomainFile.getPathname());
			}

			if (!fattrs.contains(NAME_ATTR)) {
				fattrs.add(NAME_ATTR, file.getName());
			}
			if (!fattrs.contains(PATH_ATTR)) {
				fattrs.add(PATH_ATTR, FilenameUtils.getFullPath(file.getPath()));
			}
			if (!fattrs.contains(FSRL_ATTR)) {
				fattrs.add(FSRL_ATTR, file.getFSRL());
			}
			return fattrs;
		}
	}

	private String getHTMLInfoStringForAttributes(List<FileAttributes> fileAttributesList) {
		StringBuilder sb = new StringBuilder("<html>\n<table>\n");
		sb.append("<tr><th>Property</th><th>Value</th></tr>\n");
		for (FileAttributes fattrs : fileAttributesList) {
			if (fattrs != fileAttributesList.get(0)) {
				// not first element, put a visual divider line
				sb.append("<tr><td colspan=2><hr></td></tr>");
			}
			List<FileAttribute<?>> sortedAttribs = fattrs.getAttributes();
			Collections.sort(sortedAttribs, (o1, o2) -> Integer
					.compare(o1.getAttributeType().ordinal(), o2.getAttributeType().ordinal()));

			FileAttributeTypeGroup group = null;
			for (FileAttribute<?> attr : sortedAttribs) {
				if (attr.getAttributeType().getGroup() != group) {
					group = attr.getAttributeType().getGroup();
					if (group != FileAttributeTypeGroup.GENERAL_INFO) {
						sb.append("<tr><td><b>")
								.append(group.getDescriptiveName())
								.append("</b></td><td><hr></td></tr>\n");
					}
				}
				String valStr =
					FAT_TOSTRING_FUNCS.getOrDefault(attr.getAttributeType(), PLAIN_TOSTRING)
							.apply(attr.getAttributeValue());

				String html = HTMLUtilities.escapeHTML(valStr);
				html = html.replace("\n", "<br>\n");
				sb.append("<tr><td>")
						.append(attr.getAttributeDisplayName())
						.append(":</td><td>")
						.append(html)
						.append("</td></tr>\n");
			}
		}
		sb.append("</table>");
		return sb.toString();
	}

	//---------------------------------------------------------------------------------------------
	// static lookup tables for rendering file attributes
	//---------------------------------------------------------------------------------------------
	private static final Function<Object, String> PLAIN_TOSTRING = o -> o.toString();
	private static final Function<Object, String> SIZE_TOSTRING =
		o -> (o instanceof Long) ? FSUtilities.formatSize((Long) o) : o.toString();
	private static final Function<Object, String> UNIX_ACL_TOSTRING =
		o -> (o instanceof Number) ? String.format("%05o", (Number) o) : o.toString();
	private static final Function<Object, String> DATE_TOSTRING =
		o -> (o instanceof Date) ? FSUtilities.formatFSTimestamp((Date) o) : o.toString();
	private static final Function<Object, String> FSRL_TOSTRING =
		o -> (o instanceof FSRL) ? ((FSRL) o).toPrettyString().replace("|", "|\n\t") : o.toString();

	private static final Map<FileAttributeType, Function<Object, String>> FAT_TOSTRING_FUNCS =
		Map.ofEntries(entry(FSRL_ATTR, FSRL_TOSTRING), entry(SIZE_ATTR, SIZE_TOSTRING),
			entry(COMPRESSED_SIZE_ATTR, SIZE_TOSTRING), entry(CREATE_DATE_ATTR, DATE_TOSTRING),
			entry(MODIFIED_DATE_ATTR, DATE_TOSTRING), entry(ACCESSED_DATE_ATTR, DATE_TOSTRING),
			entry(UNIX_ACL_ATTR, UNIX_ACL_TOSTRING));
}
