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

import java.awt.Color;

import javax.swing.UIDefaults;

import ghidra.util.WebColors;

public class FlatDarkUiDefaultsMapper extends FlatUiDefaultsMapper {

	protected FlatDarkUiDefaultsMapper(UIDefaults defaults) {
		super(defaults);
	}

	@Override
	protected void pickRepresentativeValueForColorGroups() {
		super.pickRepresentativeValueForColorGroups();

		// We don't think the FlatDark LaF's view background (Trees, Tables, Lists) is dark
		// enough, so we are overriding the view group background and foreground colors
		setGroupColor(BG_VIEW_ID, new Color(0x1c1d1e));
		setGroupColor(FG_VIEW_ID, WebColors.LIGHT_GRAY);
	}

	@Override
	protected void assignNormalizedColorValues() {
		super.assignNormalizedColorValues();

		//
		// These components are initialized to "text", but we want them mapped to use
		// our view background color so that they look like normal editable widgets
		//
		overrideColor("ComboBox.background", BG_VIEW_ID);
		overrideColor("EditorPane.background", BG_VIEW_ID);
		overrideColor("FormattedTextField.background", BG_VIEW_ID);
		overrideColor("List.background", BG_VIEW_ID);
		overrideColor("PasswordField.background", BG_VIEW_ID);
		overrideColor("Table.background", BG_VIEW_ID);
		overrideColor("Table.focusCellBackground", BG_VIEW_ID);
		overrideColor("TableHeader.focusCellBackground", BG_VIEW_ID);
		overrideColor("TextField.background", BG_VIEW_ID);
		overrideColor("Tree.background", BG_VIEW_ID);
		overrideColor("Tree.textBackground", BG_VIEW_ID);
		overrideColor("TextArea.background", BG_VIEW_ID);
		overrideColor("TextArea.foreground", FG_VIEW_ID);
		overrideColor("TextPane.background", BG_VIEW_ID);
		overrideColor("TextPane.foreground", FG_VIEW_ID);
	}

}
