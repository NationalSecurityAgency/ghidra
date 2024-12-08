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
package utility.application;

import java.io.File;
import java.io.IOException;

import ghidra.framework.PluggableServiceRegistry;
import ghidra.util.Msg;

public class ApplicationSettings {
	static {
		PluggableServiceRegistry.registerPluggableService(ApplicationSettings.class,
			new ApplicationSettings());
	}

	/**
	 * Returns the directory into which application settings are stored per user, per 
	 * application version.
	 * @return the directory into which application settings are stored per user, per 
	 * application version.
	 */
	public static File getUserApplicationSettingsDirectory() {
		ApplicationSettings impl =
			PluggableServiceRegistry.getPluggableService(ApplicationSettings.class);
		return impl.doGetUserApplicationSettingsDirectory();
	}

	/**
	 * Aha!  This is where any potential subclasses can update the returned value.
	 * 
	 * @return the directory into which application settings are stored per user, per 
	 * 		   application version.
	 */
	protected File doGetUserApplicationSettingsDirectory() {
		try {
			return ApplicationUtilities.getDefaultUserTempDir("application.settings");
		}
		catch (IOException e) {
			Msg.error(ApplicationSettings.class, "Error creating application.settings directory",
				e);
			return null;
		}
	}
}
