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
package ghidra.framework.project.extensions;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;

/**
 * A class that contains an {@link ExtensionDetails} and any {@link ClassFileInfo extension points}
 * loaded from that extension.
 */
public class ExtensionInstallationInfo {

	private ExtensionDetails extension;
	private Set<ClassFileInfo> classInfos = new HashSet<>();

	/**
	 * {@return information for each installed extension}
	 */
	public static Set<ExtensionInstallationInfo> get() {
		Set<ExtensionDetails> extensions = ExtensionUtils.getInstalledExtensions();
		return loadExtensionPointInfo(extensions);
	}

	private ExtensionInstallationInfo(ExtensionDetails extension) {
		this.extension = extension;
	}

	private static Set<ExtensionInstallationInfo> loadExtensionPointInfo(
			Set<ExtensionDetails> extensions) {

		// Map all class infos by module so we can then do one lookup per extension.  Standardize on
		// forward slashes for consistency.
		Set<ClassFileInfo> extensionPoints = ClassSearcher.getExtensionPointInfo();
		Map<String, List<ClassFileInfo>> classesByModule = extensionPoints.stream()
				.collect(Collectors.groupingBy(ClassFileInfo::module));

		Set<ExtensionInstallationInfo> results = new HashSet<>();
		for (ExtensionDetails extension : extensions) {

			ExtensionInstallationInfo info = new ExtensionInstallationInfo(extension);
			results.add(info);
			File installDir = extension.getInstallDir();
			String path = installDir.getAbsolutePath();
			List<ClassFileInfo> classes = classesByModule.get(path);
			if (classes != null) {
				info.classInfos.addAll(classes);
			}
		}

		return results;
	}

	public ExtensionDetails getExtension() {
		return extension;
	}

	public Set<ClassFileInfo> getClassInfos() {
		return classInfos;
	}

	@Override
	public String toString() {
		return extension.toString();
	}

	@Override
	public int hashCode() {
		return Objects.hash(extension);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ExtensionInstallationInfo other = (ExtensionInstallationInfo) obj;
		return Objects.equals(extension, other.extension);
	}
}
