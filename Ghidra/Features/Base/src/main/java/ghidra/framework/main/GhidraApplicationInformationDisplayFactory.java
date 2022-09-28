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
package ghidra.framework.main;

import java.awt.Image;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.framework.ApplicationInformationDisplayFactory;
import generic.theme.GIcon;
import ghidra.app.util.GenericHelpTopics;
import ghidra.util.HelpLocation;

public class GhidraApplicationInformationDisplayFactory
		extends ApplicationInformationDisplayFactory {

	@Override
	protected List<Image> doGetWindowIcons() {
		List<Image> list = new ArrayList<>();
		list.add(image("icon.base.application.16"));
		list.add(image("icon.base.application.24"));
		list.add(image("icon.base.application.32"));
		list.add(image("icon.base.application.40"));
		list.add(image("icon.base.application.48"));
		list.add(image("icon.base.application.64"));
		list.add(image("icon.base.application.128"));
		list.add(image("icon.base.application.256"));
		return list;
	}

	private Image image(String id) {
		return new GIcon(id).getImageIcon().getImage();
	}

	@Override
	protected String doCreateSplashScreenTitle() {
		return "Welcome To Ghidra";
	}

	@Override
	protected String doCreateAboutTitle() {
		return "About Ghidra";
	}

	@Override
	protected HelpLocation doCreateHelpLocation() {
		return new HelpLocation(GenericHelpTopics.ABOUT, "About_Ghidra");
	}

	@Override
	protected JComponent doCreateSplashScreenComponent() {
		return new InfoPanel();
	}

	@Override
	public Icon doGetHomeIcon() {
		return new GIcon("icon.base.application.home");
	}

	@Override
	protected Runnable doGetHomeCallback() {
		return () -> {
			FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
			frontEndTool.toFront();
		};
	}
}
