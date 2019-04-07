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

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.framework.ApplicationInformationDisplayFactory;
import ghidra.app.util.GenericHelpTopics;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class GhidraApplicationInformationDisplayFactory
		extends ApplicationInformationDisplayFactory {

	@Override
	protected List<Image> doGetWindowIcons() {
		List<Image> list = new ArrayList<>();
		list.add(ResourceManager.loadImage("images/GhidraIcon16.png").getImage());
		list.add(ResourceManager.loadImage("images/GhidraIcon24.png").getImage());
		list.add(ResourceManager.loadImage("images/GhidraIcon32.png").getImage());
		list.add(ResourceManager.loadImage("images/GhidraIcon40.png").getImage());
		list.add(ResourceManager.loadImage("images/GhidraIcon48.png").getImage());
		list.add(ResourceManager.loadImage("images/GhidraIcon64.png").getImage());
		list.add(ResourceManager.loadImage("images/GhidraIcon128.png").getImage());
		list.add(ResourceManager.loadImage("images/GhidraIcon256.png").getImage());
		return list;
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
	public ImageIcon doGetHomeIcon() {
		return ResourceManager.loadImage("images/GhidraIcon16.png");
	}

	@Override
	protected Runnable doGetHomeCallback() {
		return () -> {
			FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
			frontEndTool.toFront();
		};
	}
}
