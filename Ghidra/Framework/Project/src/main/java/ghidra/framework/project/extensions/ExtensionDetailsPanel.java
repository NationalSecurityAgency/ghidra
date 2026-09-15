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
package ghidra.framework.project.extensions;

import java.awt.Font;
import java.awt.Point;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import javax.swing.JViewport;

import docking.widgets.table.threaded.ThreadedTableModelListener;
import generic.theme.*;
import ghidra.framework.plugintool.dialog.AbstractDetailsPanel;
import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.extensions.ExtensionDetails;

/**
 * Panel that shows information about the selected extension in the {@link ExtensionTablePanel}. This
 * is essentially a view into the {@link ExtensionDetails} for the extension.
 * <p>
 * Note: The text is rendered as html to allow proper formatting (colors/font weight).
 */
class ExtensionDetailsPanel extends AbstractDetailsPanel {

	private static final GColor FG_COLOR_AUTHOR =
		new GColor("color.fg.extensionpanel.details.author");
	private static final GColor FG_COLOR_DATE = new GColor("color.fg.extensionpanel.details.date");
	private static final GColor FG_COLOR_DESCRIPTION =
		new GColor("color.fg.extensionpanel.details.description");
	private static final GColor FG_COLOR_NAME = new GColor("color.fg.extensionpanel.details.name");
	private static final GColor FG_COLOR_PATH = new GColor("color.fg.extensionpanel.path");
	private static final GColor FG_COLOR_TITLE =
		new GColor("color.fg.extensionpanel.details.title");
	private static final GColor FG_COLOR_VERSION =
		new GColor("color.fg.extensionpanel.details.version");

	private static final GColor FG_COLOR_CLASSES_HEADER =
		new GColor("color.fg.extensionpanel.details.classes.header");
	private static final GColor FG_COLOR_CLASSES_TYPE =
		new GColor("color.fg.extensionpanel.details.classes.type");

	/** Attribute sets define the visual characteristics for each field */
	private GAttributes nameAttrSet;
	private GAttributes descrAttrSet;
	private GAttributes authorAttrSet;
	private GAttributes createdOnAttrSet;
	private GAttributes versionAttrSet;
	private GAttributes pathAttrSet;

	private GAttributes classesHeaderAttrSet;
	private GAttributes classesTypeAtrrSet;

	private ExtensionRowObject currentRowObject;

	ExtensionDetailsPanel(ExtensionTablePanel tablePanel) {
		createFieldAttributes();
		createMainPanel();

		// Any time the table is reloaded or a new selection is made, we want to reload this
		// panel. This ensures we are always viewing data for the currently-selected item.
		tablePanel.getTableModel().addThreadedTableModelListener(new ThreadedTableModelListener() {

			@Override
			public void loadPending() {
				// do nothing
			}

			@Override
			public void loadingStarted() {
				// do nothing
			}

			@Override
			public void loadingFinished(boolean wasCancelled) {
				setDescription(tablePanel.getSelectedItem());
			}
		});

		tablePanel.getTable().getSelectionModel().addListSelectionListener(e -> {
			setDescription(tablePanel.getSelectedItem());
		});
	}

	@Override
	protected void refresh() {

		JViewport vp = sp.getViewport();
		Point p = vp.getViewPosition();

		setDescription(currentRowObject);

		// restore the viewer's scrolled position to avoid jumping around
		vp.setViewPosition(p);
	}

	private void setDescription(ExtensionRowObject ro) {

		this.currentRowObject = ro;
		clear();
		if (ro == null) {
			return;
		}

		ExtensionDetails details = ro.getExtension();

		StringBuilder buffer = new StringBuilder("<html>");

		buffer.append("<H2>Extension Properties</H2>");

		buffer.append("<TABLE cellpadding=2>");

		insertRowTitle(buffer, "Name");
		insertRowValue(buffer, details.getName(), nameAttrSet);

		insertRowTitle(buffer, "Description");
		insertRowValue(buffer, details.getDescription(), descrAttrSet);

		insertRowTitle(buffer, "Author");
		insertRowValue(buffer, details.getAuthor(), authorAttrSet);

		insertRowTitle(buffer, "Created-on");
		String date = details.getCreatedOn();
		insertRowValue(buffer, date, createdOnAttrSet);

		insertRowTitle(buffer, "Version");

		String version = details.getVersion();
		if (version.equals("@extversion@")) {
			insertRowValue(buffer, "", versionAttrSet);
		}
		else {
			insertRowValue(buffer, version, versionAttrSet);
		}

		String installPath = details.getInstallPath();
		if (installPath != null) {
			insertRowTitle(buffer, "Install Path");
			insertRowValue(buffer, installPath, pathAttrSet);
		}

		buffer.append("</TABLE>");

		addExtensionClasses(buffer, ro);

		textLabel.setText(buffer.toString());
		sp.getViewport().setViewPosition(new Point(0, 0));
	}

	private void addExtensionClasses(StringBuilder buffer, ExtensionRowObject ro) {

		Set<ClassFileInfo> infos = ro.getClassInfos();
		if (infos.isEmpty()) {
			return;
		}

		buffer.append("<BR><CENTER><HR></CENTER><BR>");

		buffer.append("<H2>Provided Extension Points</H2>");

		buffer.append("<TABLE cellpadding=4>");

		buffer.append("<TR>");
		insertHeader(buffer, "Type");
		insertHeader(buffer, "Implementations");
		buffer.append("</TR>");

		Map<String, Set<ClassFileInfo>> classesByType = infos.stream()
				.collect(
					Collectors.groupingBy(
						ClassFileInfo::suffix,
						Collectors.toSet()));

		Set<Entry<String, Set<ClassFileInfo>>> entries = classesByType.entrySet();
		for (Entry<String, Set<ClassFileInfo>> entry : entries) {
			String type = entry.getKey();

			insertRowTitle(buffer, type, classesTypeAtrrSet);

			StringBuilder infosBuffer = new StringBuilder();
			Set<ClassFileInfo> typeInfos = entry.getValue();
			for (ClassFileInfo typeInfo : typeInfos) {
				String name = typeInfo.name();
				String shortName = getShortName(name);
				insertHTMLLine(infosBuffer, shortName, descrAttrSet);
			}

			buffer.append("<TD VALIGN=\"TOP\" WIDTH=\"80%\">");
			buffer.append(infosBuffer.toString());
			buffer.append("</TD>");
			buffer.append("</TR>");
		}

		buffer.append("</TABLE>");

	}

	private String getShortName(String name) {
		int index = name.lastIndexOf('.');
		if (index < 0) {
			return name; // no package
		}
		return name.substring(index + 1);
	}

	protected void insertHeader(StringBuilder buffer, String rowName) {

		buffer.append("<TH VALIGN=\"TOP\" ALIGN=\"LEFT\">");
		insertHTMLLine(buffer, rowName, classesHeaderAttrSet);
		buffer.append("</TH>");
	}

	@Override
	protected void createFieldAttributes() {

		Font font = Gui.getFont(FONT_DEFAULT);
		titleAttrs = new GAttributes(font, FG_COLOR_TITLE);
		nameAttrSet = new GAttributes(font, FG_COLOR_NAME);
		descrAttrSet = new GAttributes(font, FG_COLOR_DESCRIPTION);
		authorAttrSet = new GAttributes(font, FG_COLOR_AUTHOR);
		createdOnAttrSet = new GAttributes(font, FG_COLOR_DATE);
		versionAttrSet = new GAttributes(font, FG_COLOR_VERSION);
		pathAttrSet = new GAttributes(font, FG_COLOR_PATH);
		classesHeaderAttrSet = new GAttributes(font, FG_COLOR_CLASSES_HEADER);
		classesTypeAtrrSet = new GAttributes(font, FG_COLOR_CLASSES_TYPE);
	}

}
