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

import java.io.File;
import java.io.IOException;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

@Deprecated
public class JavaScriptClassLoader extends ClassLoader {
	private Map<File, Long> lastModifiedMap = new HashMap<>();

	public JavaScriptClassLoader() {
		super();
	}

	@Override
	protected synchronized Class<?> loadClass(String name, boolean resolve)
			throws ClassNotFoundException, GhidraScriptUnsupportedClassVersionError {

		ResourceFile sourceFile = getScriptSourceFile(name);
		ResourceFile classFile = getClassFile(sourceFile, name);
		if (classFile == null || !classFile.exists()) {
			return super.loadClass(name, resolve);
		}

		try {
			byte[] classBytes = FileUtilities.getBytesFromFile(classFile);
			Class<?> clazz = defineClass(name, classBytes, 0, classBytes.length);
			saveClassModifiedTime(classFile);
			return clazz;
		}
		catch (UnsupportedClassVersionError ucve) {
			throw new GhidraScriptUnsupportedClassVersionError(ucve, classFile);
		}
		catch (IOException ioe) {
			throw new ClassNotFoundException("Unable to load class bytes: " + name);
		}
	}

	private void saveClassModifiedTime(ResourceFile classFile) {
		File file = classFile.getFile(false);
		if (file != null) {
			lastModifiedMap.put(file, file.lastModified());
		}
	}

	public Long lastModified(File file) {
		return lastModifiedMap.get(file);
	}

	protected ResourceFile getClassFile(ResourceFile sourceFile, String rawName) {
		return GhidraScriptUtil.getClassFile(sourceFile, rawName);
	}

	/**
	 * Attempt to find a source file for the given class.  If we find it, then we want to use
	 * the class that is relative to that file.  Sometimes there exists multiple classes for
	 * a given name in the classpath.  In that case, we want to use the one associated with the
	 * source file, as that gives us better debugging in our development environment.
	 *
	 * @param name The name of the class for which to find a source file
	 * @return a source file from which a class file can be located.
	 */
	private ResourceFile getScriptSourceFile(String name) {
		String path = name.replace('.', '/');
		int innerClassIndex = path.indexOf('$');
		if (innerClassIndex != -1) {
			path = path.substring(0, innerClassIndex);
		}
		String sourceFilePath = path + ".java";

		// Create set to store the discovered scripts that match the provided script name.
		// Use a LinkedHashSet to preserve the order the scripts were found in so we can properly
		// choose the matching script with the highest path precedence.
		Set<ResourceFile> matchingFiles = new LinkedHashSet<ResourceFile>();

		List<ResourceFile> scriptSourceDirs = GhidraScriptUtil.getScriptSourceDirectories();
		for (ResourceFile sourceDir : scriptSourceDirs) {
			ResourceFile potentialFile = new ResourceFile(sourceDir, sourceFilePath);
			if (potentialFile.exists()) {
				matchingFiles.add(potentialFile);
			}
		}

		int matchCount = matchingFiles.size();
		if (matchCount == 1) {
			return matchingFiles.iterator().next();
		}
		else if (matchCount > 1) {
			ResourceFile match = matchingFiles.iterator().next();
			Msg.warn(this,
				"Found " + matchCount + " source files named " + name + ".  Using: " + match);
			return match;
		}

		return null;
	}

}
