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
package ghidra.feature.fid.debug;

import java.awt.GridLayout;
import java.awt.event.ActionListener;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.lang.LanguageID;

/**
 * Class representing the debug display panel for a function record.
 */
public class FidFunctionDebugPanel extends JPanel {
	private final FidService service;
	private final FidQueryService fidQueryService;
	private final FunctionRecord functionRecord;

	/**
	 * Creates the panel.
	 * @param service the FID database service
	 * @param functionRecord the function record to debug
	 */
	public FidFunctionDebugPanel(FidService service, FidQueryService fidQueryService,
			FunctionRecord functionRecord) {
		this.service = service;
		this.fidQueryService = fidQueryService;
		this.functionRecord = functionRecord;
		initialize();
	}

	/**
	 * Convenience method to add a button.
	 * @param text the text of the button
	 * @param listener the action listener for when the button is pressed
	 */
	private void addButton(String text, ActionListener listener) {
		JButton button = new JButton(text);
		button.addActionListener(listener);
		button.setHorizontalAlignment(SwingConstants.LEFT);
		button.setFont(FidDebugUtils.MONOSPACED_FONT);
		add(button);
	}

	/**
	 * Convenience method to add a label.
	 * @param text the text of the label
	 */
	private void addLabel(String text) {
		JLabel label = new GDLabel(text);
		label.setHorizontalAlignment(SwingConstants.LEFT);
		label.setFont(FidDebugUtils.MONOSPACED_FONT);
		add(label);
	}

	/**
	 * Layout the panel, add the components and listeners.
	 */
	private void initialize() {
		setLayout(new GridLayout(0, 1));

		LibraryRecord libraryRecord = fidQueryService.getLibraryForFunction(functionRecord);
		LanguageID languageID = libraryRecord.getGhidraLanguageID();

		addLabel(String.format("%s %s %s (%s)", libraryRecord.getLibraryFamilyName(),
			libraryRecord.getLibraryVersion(), libraryRecord.getLibraryVariant(),
			languageID.getIdAsString()));

		addButton(String.format("0x%016x", functionRecord.getID()),
			e -> FidDebugUtils.searchByFunctionID(functionRecord.getID(), service,
				fidQueryService));

		addButton(functionRecord.getName(),
			e -> FidDebugUtils.searchByName(functionRecord.getName(), service, fidQueryService));

		addButton(shorten(functionRecord.getDomainPath()),
			e -> FidDebugUtils.searchByDomainPath(functionRecord.getDomainPath(), service,
				fidQueryService));

		addLabel(String.format("Entry Point: 0x%x", functionRecord.getEntryPoint()));

		addButton(
			String.format("FH: 0x%016x (%d)", functionRecord.getFullHash(),
				functionRecord.getCodeUnitSize()),
			e -> FidDebugUtils.searchByFullHash(functionRecord.getFullHash(), service,
				fidQueryService)

		);

		addButton(
			String.format("XH: 0x%016x (+%d)", functionRecord.getSpecificHash(),
				functionRecord.getSpecificHashAdditionalSize()),
			e -> FidDebugUtils.searchBySpecificHash(functionRecord.getSpecificHash(), service,
				fidQueryService));

		addLabel(String.format("%s %s %s %s %s",
			functionRecord.hasTerminator() ? "" : "(unterminated function)",
			functionRecord.autoFail() ? "(auto-fail)" : "",
			functionRecord.autoPass() ? "(auto-pass)" : "",
			functionRecord.isForceSpecific() ? "(force-specific)" : "",
			functionRecord.isForceRelation() ? "(force-relation)" : ""));
	}

	private static final int MAGIC_MAXIMUM_LENGTH = 30;

	/**
	 * Shortens a domain path to make it as readable as possible without flying off the screen.
	 * @param domainPath the string to shorten
	 * @return a shortened string
	 */
	private static String shorten(String domainPath) {
		String[] splits = domainPath.split("/");
		StringBuilder sb = new StringBuilder();
		for (int ii = splits.length - 1; ii >= 0; --ii) {
			sb.insert(0, splits[ii]);
			if (ii != 0) {
				sb.insert(0, "/");
			}
			if (sb.length() >= MAGIC_MAXIMUM_LENGTH) {
				break;
			}
		}
		String result = sb.toString();
		if (result.length() < domainPath.length()) {
			result = "..." + result;
		}
		return result;
	}
}
