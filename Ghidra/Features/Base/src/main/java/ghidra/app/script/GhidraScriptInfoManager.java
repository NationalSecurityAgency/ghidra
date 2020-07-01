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
package ghidra.app.script;

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.util.Msg;

/**
 * A utility class for managing script directories and ScriptInfo objects.
 */
public class GhidraScriptInfoManager {

	private Map<ResourceFile, ScriptInfo> scriptFileToInfoMap = new HashMap<>();
	private Map<String, List<ResourceFile>> scriptNameToFilesMap = new HashMap<>();

	/**
	 * clear stored metadata
	 */
	public void dispose() {
		clearMetadata();
	}

	/**
	 * clear ScriptInfo metadata cached by GhidraScriptUtil
	 */
	public void clearMetadata() {
		scriptFileToInfoMap.clear();
		scriptNameToFilesMap.clear();
	}

	/**
	 * Removes the ScriptInfo object for the specified file
	 * @param scriptFile the script file
	 */
	public void removeMetadata(ResourceFile scriptFile) {
		scriptFileToInfoMap.remove(scriptFile);

		String name = scriptFile.getName();
		List<ResourceFile> files = scriptNameToFilesMap.get(name);
		if (files != null) {
			files.remove(scriptFile);
			if (files.isEmpty()) {
				scriptNameToFilesMap.remove(name);
			}
		}
	}

	/**
	 * get all scripts
	 * @return an iterable over all script info objects
	 */
	public Iterable<ScriptInfo> getScriptInfoIterable() {
		return () -> scriptFileToInfoMap.values().iterator();
	}

	/**
	 * Returns the script info object for the specified script file,
	 * construct a new one if necessary.
	 * 
	 * <p>Only call this method if you expect to be creating ScriptInfo objects.
	 * Prefer getExistingScriptInfo instead. 
	 * 
	 * @param scriptFile the script file
	 * @return the script info object for the specified script file
	 */
	public ScriptInfo getScriptInfo(ResourceFile scriptFile) {
		ScriptInfo info = scriptFileToInfoMap.get(scriptFile);
		if (info != null) {
			return info;
		}

		info = GhidraScriptUtil.newScriptInfo(scriptFile);
		scriptFileToInfoMap.put(scriptFile, info);
		String name = scriptFile.getName();

		List<ResourceFile> matchingFiles =
			scriptNameToFilesMap.computeIfAbsent(name, (n) -> new ArrayList<>());
		matchingFiles.add(scriptFile);
		markAnyDuplicates(matchingFiles);

		return info;
	}

	/**
	 * Returns true if a ScriptInfo object exists for
	 * the specified script file.
	 * @param scriptFile the script file
	 * @return true if a ScriptInfo object exists
	 */
	public boolean containsMetadata(ResourceFile scriptFile) {
		return scriptFileToInfoMap.containsKey(scriptFile);
	}

	/**
	 * Get {@link ScriptInfo} for {@code script} under the assumption that it's already managed.
	 * 
	 * @param script the script
	 * @return info or null if the assumption was wrong. If null is returned, an error dialog is shown
	 */
	public ScriptInfo getExistingScriptInfo(ResourceFile script) {
		if (script == null) {
			return null;
		}
		ScriptInfo info = scriptFileToInfoMap.get(script);
		if (info == null) {
			String error = (script.exists() ? "" : "non") + "existing script" + script.toString() +
				" is missing expected ScriptInfo";
			Msg.showError(GhidraScriptInfoManager.class, null, "ScriptInfo lookup", error);
		}
		return info;
	}

	/**
	 * Returns the existing script info for the given name.  The script environment limits 
	 * scripts such that names are unique.  If this method returns a non-null value, then the 
	 * name given name is taken.
	 * 
	 * @param scriptName the name of the script for which to get a ScriptInfo
	 * @return a ScriptInfo matching the given name; null if no script by that name is known to
	 *         the script manager
	 */
	public ScriptInfo getExistingScriptInfo(String scriptName) {
		List<ResourceFile> matchingFiles = scriptNameToFilesMap.get(scriptName);
		if (matchingFiles == null || matchingFiles.isEmpty()) {
			return null;
		}
		return scriptFileToInfoMap.get(matchingFiles.get(0));
	}

	/**
	 * Looks through all of the current {@link ScriptInfo}s to see if one already exists with 
	 * the given name.
	 * @param scriptName The name to check
	 * @return true if the name is not taken by an existing {@link ScriptInfo}.
	 */
	public boolean alreadyExists(String scriptName) {
		return getExistingScriptInfo(scriptName) != null;
	}

	private void markAnyDuplicates(List<ResourceFile> files) {
		boolean isDuplicate = files.size() > 1;
		files.forEach(f -> scriptFileToInfoMap.get(f).setDuplicate(isDuplicate));
	}

	/**
	 * Updates every known script's duplicate value. 
	 */
	public void refreshDuplicates() {
		scriptNameToFilesMap.values().forEach(files -> {
			boolean isDuplicate = files.size() > 1;
			files.forEach(file -> scriptFileToInfoMap.get(file).setDuplicate(isDuplicate));
		});
	}

	/**
	 * Uses the given name to find a matching script.  This method only works because of the
	 * limitation that all script names in Ghidra must be unique.  If the given name has multiple
	 * script matches, then a warning will be logged.
	 * 
	 * @param scriptName The name for which to find a script
	 * @return The ScriptInfo that has the given name
	 */
	public ScriptInfo findScriptInfoByName(String scriptName) {
		List<ResourceFile> matchingFiles = scriptNameToFilesMap.get(scriptName);
		if (matchingFiles != null && !matchingFiles.isEmpty()) {
			ScriptInfo info = scriptFileToInfoMap.get(matchingFiles.get(0));
			if (matchingFiles.size() > 1) {
				Msg.warn(GhidraScriptInfoManager.class, "Found duplicate scripts for name: " +
					scriptName + ".  Binding to script: " + info.getSourceFile());
			}
			return info;
		}

		// don't search in paths
		return null;
	}
}
