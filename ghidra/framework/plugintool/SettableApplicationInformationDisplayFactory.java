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
package ghidra.framework.plugintool;

import java.awt.Image;
import java.util.List;

import javax.swing.ImageIcon;

import docking.framework.ApplicationInformationDisplayFactory;

public class SettableApplicationInformationDisplayFactory extends
		ApplicationInformationDisplayFactory {

	private ImageIcon splashIcon;
	private List<Image> windowsIcons;
	private ImageIcon homeIcon;
	private Runnable homeCallback;

	@Override
	protected ImageIcon getSplashScreenIcon128() {
		if (splashIcon != null) {
			return splashIcon;
		}
		return super.getSplashScreenIcon128();
	}

	@Override
	protected List<Image> doGetWindowIcons() {
		if (windowsIcons != null) {
			return windowsIcons;
		}
		return super.doGetWindowIcons();
	}

	@Override
	public ImageIcon doGetHomeIcon() {
		return homeIcon;
	}

	@Override
	protected Runnable doGetHomeCallback() {
		if (homeCallback == null) {
			return super.doGetHomeCallback();
		}
		return homeCallback;
	}

	public void setSplashIcon128(ImageIcon splashIcon) {
		this.splashIcon = splashIcon;
	}

	public void setWindowsIcons(List<Image> windowsIcons) {
		this.windowsIcons = windowsIcons;
	}

	public void setHomeIcon(ImageIcon icon) {
		this.homeIcon = icon;
	}

	public void setHomeCallback(Runnable callback) {
		this.homeCallback = callback;
	}
}
