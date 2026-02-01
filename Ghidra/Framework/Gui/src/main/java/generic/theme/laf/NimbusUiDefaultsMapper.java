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
	protected void registerIgnoredJavaIds() {
		super.registerIgnoredJavaIds();
		ignoredJavaIds.add("background");

		ignoredJavaIds.add("controlLHighlight");

		ignoredJavaIds.add("nimbusAlertYellow");
		ignoredJavaIds.add("nimbusBase");
		ignoredJavaIds.add("nimbusBlueGrey");
		ignoredJavaIds.add("nimbusDisabledText");
		ignoredJavaIds.add("nimbusFocus");
		ignoredJavaIds.add("nimbusGreen");
		ignoredJavaIds.add("nimbusInfoBlue");
		ignoredJavaIds.add("nimbusOrange");
		ignoredJavaIds.add("nimbusRed");
		ignoredJavaIds.add("nimbusSelectedText");
		ignoredJavaIds.add("nimbusSelection");
		ignoredJavaIds.add("nimbusSelectionBackground");

	}

	@Override
	protected void pickRepresentativeValueForColorGroups() {

		// different from base class
		setGroupColorUsingJavaRepresentative(BG_CONTROL_ID, "Button.background");
		setGroupColorUsingJavaRepresentative(FG_CONTROL_ID, "Button.foreground");
		setGroupColorUsingJavaRepresentative(BG_BORDER_ID, "nimbusBorder");
		setGroupColorUsingJavaRepresentative(BG_VIEW_ID, "nimbusLightBackground");
		setGroupColorUsingJavaRepresentative(FG_VIEW_ID, "controlText");

		// the following are the same as the base class (we can't just call super because
		// it will report errors for missing lafIds such as "window"

		setGroupColorUsingJavaRepresentative(BG_VIEW_SELECTED_ID, "textHighlight");
		setGroupColorUsingJavaRepresentative(FG_VIEW_SELECTED_ID, "textHighlightText");
		setGroupColorUsingJavaRepresentative(FG_DISABLED_ID, "textInactiveText");
		setGroupColorUsingJavaRepresentative(BG_TOOLTIP_ID, "info");
		setGroupColorUsingJavaRepresentative(FG_TOOLTIP_ID, "infoText");
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
