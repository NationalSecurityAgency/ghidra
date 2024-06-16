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
// Text-dump all data types from the user-specified DataTypeManager to the user-specified file.
//
//@category Data Types
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.util.Iterator;

import javax.swing.JLabel;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.text.View;

import docking.widgets.OptionDialog;
import generic.text.TextLayoutGraphics;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.ToolTipUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;

public class DeveloperDumpAllTypesScript extends GhidraScript {

	@Override
	protected void run() throws Exception, CancelledException {

		DataTypeManager manager = userChooseDataTypeManager();
		if (manager == null) {
			return;
		}

		File dumpFile = askFile("Choose an output file", "OK");
		if (dumpFile == null) {
			Msg.info(this, "Canceled execution due to no output file");
			return;
		}
		if (dumpFile.exists()) {
			if (!askYesNo("Confirm Overwrite", "Overwrite file: " + dumpFile.getName())) {
				Msg.info(this, "Operation canceled");
				return;
			}
		}
		FileWriter fileWriter = new FileWriter(dumpFile);

		String message = "Outputting DataTypes from: " + manager.getName();

		Iterator<DataType> allDataTypes = manager.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			monitor.checkCancelled();
			DataType dataType = allDataTypes.next();
			DataTypePath dataTypePath = dataType.getDataTypePath();
			String pathString = dataTypePath.toString();
			String htmlString = ToolTipUtils.getToolTipText(dataType);
			String plainString = Swing.runNow(() -> {
				return fromHTML(htmlString);
			});
			fileWriter.append(pathString);
			fileWriter.append("\n");
			fileWriter.append(plainString);
			fileWriter.append("\n");
			fileWriter.append("------------------------------------------------------------\n");
		}
		fileWriter.close();

		message = "Results located in: " + dumpFile.getAbsoluteFile();
		monitor.setMessage(message);
		Msg.info(this, message);
	}

	// Method below copied from HTMLUtilities and modified to set a fixed size so that it
	// is consistent between runs between tools over the course of time.
	/**
	 * Checks the given string to see it is HTML, according to {@link BasicHTML} and then
	 * will return the text without any markup tags if it is.
	 *
	 * @param text the text to convert
	 * @return the converted String
	 */
	private static String fromHTML(String text) {

		if (text == null) {
			return null;
		}

		if (!BasicHTML.isHTMLString(text)) {
			// the message may still contain HTML, but that is something we don't handle
			return text;
		}

		//
		// Use the label's builtin handling of HTML text via the HTMLEditorKit
		//
		Swing.assertSwingThread("This method must be called on the Swing thread");
		JLabel label = new JLabel(text) {
			@Override
			public void paint(Graphics g) {
				// we cannot use paint, as we are not parented; change paint to call
				// something that works
				super.paintComponent(g);
			}
		};
		View v = (View) label.getClientProperty(BasicHTML.propertyKey);
		if (v == null) {
			return text;
		}

		//
		// Use some magic to turn the painting into text
		//
		//Dimension size = label.getPreferredSize();
		Dimension size = new Dimension(500, 500);
		label.setBounds(new Rectangle(0, 0, size.width, size.height));

		// Note: when laying out an unparented label, the y value will be half of the height
		Rectangle bounds =
			new Rectangle(-size.width, -size.height, size.width * 2, size.height * 10);

		TextLayoutGraphics g = new TextLayoutGraphics();

		g.setClip(bounds);
		label.paint(g);
		g.flush();
		String raw = g.getBuffer();
		raw = raw.trim(); // I can't see any reason to keep leading/trailing newlines/whitespace

		String updated = replaceKnownSpecialCharacters(raw);

		//
		// Unfortunately, the label adds odd artifacts to the output, like newlines after
		// formatting tags (like <B>, <FONT>, etc).   So, just normalize the text, not
		// preserving any of the line breaks.
		//
		// Note: Calling this method here causes unwanted removal of newlines.  If the original
		//       need for this call is found, this can be revisited.
		//       (see history for condense() code)
		// String condensed = condense(updated);
		return updated;
	}

	// Copied from HTMLUtilities
	/**
	 * A method to remove characters from the given string that are output by the HTML
	 * conversion process when going from HTML to plain text.
	 *
	 * @param s the string to be updated
	 * @return the updated String
	 */
	private static String replaceKnownSpecialCharacters(String s) {
		StringBuilder buffy = new StringBuilder();

		s.chars().forEach(c -> {
			switch (c) {
				case 0xA0:
					buffy.append((char) 0x20);
					break;
				default:
					buffy.append((char) c);
			}
		});

		return buffy.toString();
	}

	private DataTypeManager userChooseDataTypeManager() {
		PluginTool tool = state.getTool();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
		String names[] = new String[dataTypeManagers.length];
		String initialDtmChoice = names[0];
		try {
			initialDtmChoice = currentProgram.getDataTypeManager().getName();
		}
		catch (Exception e) {
			// Ignore... assuming no program or dtm.
		}
		for (int i = 0; i < dataTypeManagers.length; i++) {
			names[i] = dataTypeManagers[i].getName();
		}
		String userChoice =
			OptionDialog.showInputChoiceDialog(null, "Choose a Data Type Manager or Cancel",
				"Choose", names, initialDtmChoice, OptionDialog.PLAIN_MESSAGE);
		if (userChoice == null) {
			return null;
		}
		for (int i = 0; i < dataTypeManagers.length; i++) {
			if (names[i].contentEquals(userChoice)) {
				return dataTypeManagers[i];
			}
		}
		return null; // should not reach this line.
	}

}
