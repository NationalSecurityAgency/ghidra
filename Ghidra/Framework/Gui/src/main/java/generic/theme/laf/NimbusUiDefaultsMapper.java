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
package generic.theme.laf;

import static generic.theme.SystemThemeIds.*;

import javax.swing.UIDefaults;

import generic.theme.*;

public class NimbusUiDefaultsMapper extends UiDefaultsMapper {

	protected NimbusUiDefaultsMapper(UIDefaults defaults) {
		super(defaults);
	}

	@Override
	protected void registerIgnoredLafIds() {
		super.registerIgnoredLafIds();
		ignoredLafIds.add("background");

		ignoredLafIds.add("controlLHighlight");

		ignoredLafIds.add("nimbusAlertYellow");
		ignoredLafIds.add("nimbusBase");
		ignoredLafIds.add("nimbusBlueGrey");
		ignoredLafIds.add("nimbusDisabledText");
		ignoredLafIds.add("nimbusFocus");
		ignoredLafIds.add("nimbusGreen");
		ignoredLafIds.add("nimbusInfoBlue");
		ignoredLafIds.add("nimbusOrange");
		ignoredLafIds.add("nimbusRed");
		ignoredLafIds.add("nimbusSelectedText");
		ignoredLafIds.add("nimbusSelection");
		ignoredLafIds.add("nimbusSelectionBackground");

	}

	@Override
	protected void assignSystemColorValues() {

		// different from base class
		assignSystemColorFromLafId(BG_CONTROL_ID, "Button.background");
		assignSystemColorFromLafId(FG_CONTROL_ID, "Button.foreground");
		assignSystemColorFromLafId(BG_BORDER_ID, "nimbusBorder");
		assignSystemColorFromLafId(BG_VIEW_ID, "nimbusLightBackground");
		assignSystemColorFromLafId(FG_VIEW_ID, "controlText");

		// the following are the same as the base class (we can't just call super because
		// it will report errors for missing lafIds such as "window"

		assignSystemColorFromLafId(BG_VIEW_SELECTED_ID, "textHighlight");
		assignSystemColorFromLafId(FG_VIEW_SELECTED_ID, "textHighlightText");
		assignSystemColorFromLafId(FG_DISABLED_ID, "textInactiveText");
		assignSystemColorFromLafId(BG_TOOLTIP_ID, "info");
		assignSystemColorFromLafId(FG_TOOLTIP_ID, "infoText");
	}

	@Override
	protected GThemeValueMap extractColorFontAndIconValuesFromDefaults() {
		// Nimbus always uses "info" to paint its tooltip and it appears they forgot to update
		// that value to the value they assigned to the "ToolTip.background. So we fix it here
		// before extracting the values from the UIDefaults
		defaults.put("info", defaults.getColor("ToolTip.background"));
		return super.extractColorFontAndIconValuesFromDefaults();
	}

	@Override
	protected void installGColorsIntoUIDefaults() {
		super.installGColorsIntoUIDefaults();

		// The Nimbus selected text field color is not honored if the value is a ColorUIResource.
		// We install GColorUIResources by default.  Thus, our setting for this particular 
		// attribute was being ignored.   We set it here to be a GColor, which causes Nimbus 
		// to honor the value.  We may need to add more entries here as they are discovered.

		defaults.put("TextField.selectionForeground",
			new GColor(SystemThemeIds.FG_VIEW_SELECTED_ID));
	}

}
