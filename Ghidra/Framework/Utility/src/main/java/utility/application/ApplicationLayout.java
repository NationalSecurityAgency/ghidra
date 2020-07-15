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
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.GModule;
import utilities.util.FileUtilities;

/**
 * The Application Layout base class defines the customizable elements of the application's 
 * directory structure.  Create a subclass to define a custom layout.
 * <p>
 * If a layout changes in a significant way, the 
 * {@link ApplicationProperties#APPLICATION_LAYOUT_VERSION_PROPERTY} should be incremented so 
 * external things like Eclipse GhidraDev know to look in different places for things.
 */
public abstract class ApplicationLayout {

	protected ApplicationProperties applicationProperties;
	protected Collection<ResourceFile> applicationRootDirs;
	protected ResourceFile applicationInstallationDir;
	protected Map<String, GModule> modules;
	protected File userTempDir;
	protected File userCacheDir;
	protected File userSettingsDir;
	protected ResourceFile patchDir;
	protected ResourceFile extensionArchiveDir;
	protected List<ResourceFile> extensionInstallationDirs;

	/**
	 * Gets the application properties from the application layout
	 * 
	 * @return The application properties.  Should never be null.
	 */
	public final ApplicationProperties getApplicationProperties() {
		return applicationProperties;
	}

	/**
	 * Gets the application root directories from the application layout.
	 * 
	 * @return A collection of application root directories (or null if not set).
	 */
	public final Collection<ResourceFile> getApplicationRootDirs() {
		return applicationRootDirs;
	}

	/**
	 * Gets the application installation directory from the application layout.
	 * 
	 * @return The application installation directory (or null if not set).
	 */
	public final ResourceFile getApplicationInstallationDir() {
		return applicationInstallationDir;
	}

	/**
	 * Gets the application's modules from the application layout.
	 * 
	 * @return The application's modules as a map (mapping module name to module for convenience).
	 */
	public final Map<String, GModule> getModules() {
		return modules;
	}

	/**
	 * Gets the user temp directory from the application layout.
	 * 
	 * @return The user temp directory (or null if not set).
	 */
	public final File getUserTempDir() {
		return userTempDir;
	}

	/**
	 * Gets the user cache directory from the application layout.
	 * 
	 * @return The user cache directory (or null if not set).
	 */
	public final File getUserCacheDir() {
		return userCacheDir;
	}

	/**
	 * Gets the user settings directory from the application layout.
	 * 
	 * @return The user settings directory (or null if not set).
	 */
	public final File getUserSettingsDir() {
		return userSettingsDir;
	}

	/**
	 * Returns the directory where archived application Extensions are stored.
	 * 
	 * @return the application Extensions archive directory.  Could be null if the 
	 *   {@link ApplicationLayout} does not support application Extensions.
	 * 
	 */
	public final ResourceFile getExtensionArchiveDir() {
		return extensionArchiveDir;
	}

	/**
	 * Returns an {@link List ordered list} of the application Extensions installation directories.
	 * 
	 * @return an {@link List ordered list} of the application Extensions installation directories.
	 *   Could be empty if the {@link ApplicationLayout} does not support application Extensions.
	 */
	public final List<ResourceFile> getExtensionInstallationDirs() {
		return extensionInstallationDirs;
	}

	/**
	 * Returns the location of the application patch directory.  The patch directory can be
	 * used to modify existing code within a distribution.
	 * @return the patch directory; may be null
	 */
	public final ResourceFile getPatchDir() {
		return patchDir;
	}

	/**
	 * Creates the application's user directories (or ensures they already exist).
	 *  
	 * @throws IOException if there was a problem creating the application's user directories.
	 */
	public final void createUserDirs() throws IOException {
		if (userTempDir != null) {
			if (!FileUtilities.mkdirs(userTempDir)) {
				throw new IOException("Failed to create user temp directory: " + userTempDir);
			}
			FileUtilities.setOwnerOnlyPermissions(userTempDir);
		}

		if (userCacheDir != null) {
			if (!FileUtilities.mkdirs(userCacheDir)) {
				throw new IOException("Failed to create user cache directory: " + userCacheDir);
			}
			FileUtilities.setOwnerOnlyPermissions(userCacheDir);
		}

		if (userSettingsDir != null) {
			if (!FileUtilities.mkdirs(userSettingsDir)) {
				throw new IOException(
					"Failed to create user settings directory: " + userSettingsDir);
			}
			FileUtilities.setOwnerOnlyPermissions(userSettingsDir);
		}
	}

	/**
	 * Checks whether or not the application is using a "single jar" layout.  Custom application 
	 * layouts that extend this class can override this method once they determine they are in 
	 * single jar mode.
	 * 
	 * @return true if the application is using a "single jar" layout; otherwise, false.
	 */
	public boolean inSingleJarMode() {
		return false;
	}
}
