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
package ghidra.util.extensions;

import java.io.File;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.apache.logging.log4j.Logger;

import utilities.util.FileUtilities;

/**
 * A collection of all extensions found.  This class provides methods processing duplicates and
 * managing extensions marked for removal.
 */
public class Extensions {

	private Logger log;
	private Map<String, List<ExtensionDetails>> extensionsByName = new HashMap<>();

	Extensions(Logger log) {
		this.log = log;
	}

	/**
	 * Returns all extensions matching the given details
	 * @param e the extension details to match
	 * @return all matching extensions
	 */
	public List<ExtensionDetails> getMatchingExtensions(ExtensionDetails e) {
		return extensionsByName.computeIfAbsent(e.getName(), name -> new ArrayList<>());
	}

	/**
	 * Adds an extension to this collection of extensions
	 * @param e the extension
	 */
	void add(ExtensionDetails e) {
		extensionsByName.computeIfAbsent(e.getName(), n -> new ArrayList<>()).add(e);
	}

	/**
	 * Returns all installed extensions that are not marked for uninstall
	 * @return all installed extensions that are not marked for uninstall
	 */
	Set<ExtensionDetails> getActiveExtensions() {
		return extensionsByName.values()
				.stream()
				.filter(list -> !list.isEmpty())
				.map(list -> list.get(0))
				.filter(ext -> !ext.isPendingUninstall())
				.collect(Collectors.toSet());
	}

	/**
	 * Removes any extensions that have already been marked for removal.  This should be called
	 * before any class loading has occurred.
	 */
	void cleanupExtensionsMarkedForRemoval() {

		Set<String> names = new HashSet<>(extensionsByName.keySet());
		for (String name : names) {
			List<ExtensionDetails> extensions = extensionsByName.get(name);
			Iterator<ExtensionDetails> it = extensions.iterator();
			while (it.hasNext()) {
				ExtensionDetails extension = it.next();
				if (!extension.isPendingUninstall()) {
					continue;
				}
				if (!removeExtension(extension)) {
					log.error("Error removing extension: " + extension.getInstallPath());
				}

				it.remove();
			}

			if (extensions.isEmpty()) {
				extensionsByName.remove(name);
			}
		}
	}

	private boolean removeExtension(ExtensionDetails extension) {

		if (extension == null) {
			log.error("Extension to uninstall cannot be null");
			return false;
		}

		File installDir = extension.getInstallDir();
		if (installDir == null) {
			log.error("Extension installation path is not set; unable to delete files");
			return false;
		}

		if (FileUtilities.deleteDir(installDir)) {
			extension.setInstallDir(null);
			return true;
		}

		return false;
	}

	/**
	 * Returns all unique extensions (no duplicates) that the application is aware of
	 * @return the extensions
	 */
	Set<ExtensionDetails> get() {
		return extensionsByName.values()
				.stream()
				.filter(list -> !list.isEmpty())
				.map(list -> list.get(0))
				.collect(Collectors.toSet());
	}

	/**
	 * Returns a string representation of this collection of extensions
	 * @return a string representation of this collection of extensions
	 */
	String getAsString() {
		StringBuilder buffy = new StringBuilder();

		Set<Entry<String, List<ExtensionDetails>>> entries = extensionsByName.entrySet();
		for (Entry<String, List<ExtensionDetails>> entry : entries) {
			String name = entry.getKey();
			buffy.append("Name: ").append(name);

			List<ExtensionDetails> extensions = entry.getValue();
			if (extensions.size() == 1) {
				buffy.append(" - ").append(extensions.get(0).getInstallDir()).append('\n');
			}
			else {
				for (ExtensionDetails e : extensions) {
					buffy.append("\t").append(e.getInstallDir()).append('\n');
				}
			}
		}

		if (buffy.isEmpty()) {
			return "<no extensions installed>";
		}

		if (!buffy.isEmpty()) {
			// remove trailing newline to keep logging consistent
			buffy.deleteCharAt(buffy.length() - 1);
		}
		return buffy.toString();
	}

	/**
	 * Logs any duplicate extensions
	 */
	void reportDuplicateExtensions() {

		Set<Entry<String, List<ExtensionDetails>>> entries = extensionsByName.entrySet();
		for (Entry<String, List<ExtensionDetails>> entry : entries) {
			List<ExtensionDetails> list = entry.getValue();
			if (list.size() == 1) {
				continue;
			}

			reportDuplicateExtensionsWhenLoading(entry.getKey(), list);
		}
	}

	private void reportDuplicateExtensionsWhenLoading(String name,
			List<ExtensionDetails> extensions) {

		ExtensionDetails loadedExtension = extensions.get(0);
		File loadedInstallDir = loadedExtension.getInstallDir();

		for (int i = 1; i < extensions.size(); i++) {
			ExtensionDetails duplicate = extensions.get(i);
			log.info("Duplicate extension found '" + name + "'.  Keeping extension from " +
				loadedInstallDir + ".  Skipping extension found at " + duplicate.getInstallDir());
		}
	}

}
