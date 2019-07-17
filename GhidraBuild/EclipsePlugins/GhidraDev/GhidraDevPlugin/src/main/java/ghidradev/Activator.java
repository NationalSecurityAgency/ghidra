/* ###
 * IP: GHIDRA
 * NOTE: eclipse plugin code
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
package ghidradev;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.ui.plugin.AbstractUIPlugin;
import org.osgi.framework.BundleContext;

/**
 * The activator class controls the plug-in life cycle.
 * 
 * NOTE: Plugins declaring extensions or extension points must be implemented as a singleton.
 */
public class Activator extends AbstractUIPlugin {

	private Set<Closeable> closeSet = new HashSet<>();

	/**
	 * The plug-in ID.
	 */
	public static final String PLUGIN_ID = "GhidraDev";

	/**
	 * A system property that Ghidra sets when launching Eclipse.
	 */
	private static final String GHIDRA_INSTALL_DIR_PROPERTY = "ghidra.install.dir";

	/**
	 * The shared instance.
	 */
	private static Activator plugin;

	/**
	 * Returns the shared instance.
	 *
	 * @return the shared instance.  Could be null if the plugin is not started.
	 */
	public static Activator getDefault() {
		return plugin;
	}

	/**
	 * Registers an object to be closed when the plugin shuts down.
	 * 
	 * @param c The object to register for close on shutdown.
	 */
	public synchronized void registerCloseable(Closeable c) {
		closeSet.add(c);
	}

	/**
	 * Unregisters an object to be closed when the plugin shuts down.
	 * 
	 * @param c The object to unregister for close on shutdown.
	 */
	public synchronized void unregisterCloseable(Closeable c) {
		closeSet.remove(c);
	}

	/**
	 * Gets the installation directory of the Ghidra that launched Eclipse.
	 * 
	 * @return The installation directory of the Ghidra that launched Eclipse.  Could be null if
	 *   Ghidra did not launch Eclipse, or Ghidra did not pass along it's installation directory to
	 *   Eclipse properly.
	 */
	public File getGhidraInstallDir() {
		String ghidraInstallDirProperty = System.getProperty(GHIDRA_INSTALL_DIR_PROPERTY);
		if (ghidraInstallDirProperty != null && !ghidraInstallDirProperty.isEmpty()) {
			return new File(ghidraInstallDirProperty);
		}
		return null;
	}

	/**
	 * Checks to see if Eclipse was launched by Ghidra.
	 * 
	 * @return True if Eclipse was launched by Ghidra; otherwise, false.
	 */
	public boolean isLaunchedByGhidra() {
		return System.getProperty(GHIDRA_INSTALL_DIR_PROPERTY) != null;
	}

	@Override
	public void start(BundleContext context) throws Exception {
		super.start(context);
		plugin = this;
		EclipseMessageUtils.info("Starting " + PLUGIN_ID + " plugin");
	}

	@Override
	public void stop(BundleContext context) throws Exception {
		plugin = null;
		super.stop(context);
		EclipseMessageUtils.info("Stopping " + PLUGIN_ID + " plugin");
		
		// Close registered items
		synchronized (this) {
			for (Closeable c : closeSet) {
				if (c != null) {
					EclipseMessageUtils.info("Closing " + c);
					try {
						c.close();
					}
					catch (IOException e) {
						EclipseMessageUtils.info("Failed to close " + c);
					}
				}
			}
			closeSet.clear();
		}
	}
}
