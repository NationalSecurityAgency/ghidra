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
package ghidra.app.util.xml;

import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.util.xml.*;
import ghidra.xml.XmlElement;

class DisplaySettingsHandler {

	static boolean hasSettings(DataType dt) {
		return false;
	}

	static void writeSettings(XmlWriter writer, Settings settings) {
		XmlAttributes attrs = new XmlAttributes();

		if ((FormatSettingsDefinition.DEF.hasValue(settings))) {
			attrs.addAttribute("FORMAT", FormatSettingsDefinition.DEF.getDisplayChoice(settings));
		}

		if (PaddingSettingsDefinition.DEF.hasValue(settings)) {
			attrs.addAttribute("ZERO_PAD", PaddingSettingsDefinition.DEF.isPadded(settings) ? "y" : "n");
		}

		if (EndianSettingsDefinition.DEF.hasValue(settings)) {
			if (EndianSettingsDefinition.DEF.getChoice(settings) != EndianSettingsDefinition.DEFAULT) {
				attrs.addAttribute("ENDIAN", EndianSettingsDefinition.DEF.isBigEndian(settings, null) ? "big" : "little");
			}
		}

		if (TerminatedSettingsDefinition.DEF.hasValue(settings)) {
			attrs.addAttribute("SHOW_TERMINATOR", TerminatedSettingsDefinition.DEF.isTerminated(settings) ? "y" : "n");
		}

		if(!attrs.isEmpty()) {
			writer.writeElement("DISPLAY_SETTINGS", attrs);
		}
	}
	
	static void readSettings(XmlElement element, Settings settings) {
		if (element.hasAttribute("FORMAT")) {
			String format = element.getAttribute("FORMAT");
			FormatSettingsDefinition.DEF.setDisplayChoice(settings, format);
		}
		if (element.hasAttribute("ZERO_PAD")) {
			boolean isPad = XmlUtilities.parseBoolean(element.getAttribute("ZERO_PAD"));
			PaddingSettingsDefinition.DEF.setPadded(settings, isPad);
		}
		if (element.hasAttribute("ENDIAN")) {
			String endian = element.getAttribute("ENDIAN");
			EndianSettingsDefinition.DEF.setBigEndian(settings, endian.equals("big"));
		}
		if (element.hasAttribute("SHOW_TERMINATOR")) {
			boolean showTerminator = XmlUtilities.parseBoolean(element.getAttribute("SHOW_TERMINATOR"));
			TerminatedSettingsDefinition.DEF.setTerminated(settings, showTerminator);
		}
	}

}
