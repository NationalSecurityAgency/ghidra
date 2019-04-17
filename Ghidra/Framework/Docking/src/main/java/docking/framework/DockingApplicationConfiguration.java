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
package docking.framework;

import docking.DockingErrorDisplay;
import docking.widgets.PopupKeyStorePasswordProvider;
import ghidra.docking.util.DockingWindowsLookAndFeelUtils;
import ghidra.framework.ApplicationConfiguration;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.util.ErrorDisplay;

public class DockingApplicationConfiguration extends ApplicationConfiguration {

	private boolean showSplashScreen = true;

	@Override
	public boolean isHeadless() {
		return false;
	}

	@Override
	public ErrorDisplay getErrorDisplay() {
		return new DockingErrorDisplay();
	}

	public void setShowSplashScreen(boolean showSplashScreen) {
		this.showSplashScreen = showSplashScreen;
	}

	public boolean isShowSplashScreen() {
		return showSplashScreen;
	}

	@Override
	protected void initializeApplication() {
		super.initializeApplication();

		DockingWindowsLookAndFeelUtils.loadFromPreferences();

		if (showSplashScreen) {
			SplashScreen.showSplashScreen();
		}

		ApplicationKeyManagerFactory.setKeyStorePasswordProvider(
			new PopupKeyStorePasswordProvider());

	}

}
