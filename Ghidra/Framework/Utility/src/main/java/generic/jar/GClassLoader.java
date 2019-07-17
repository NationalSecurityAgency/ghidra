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
package generic.jar;

import java.io.File;
import java.net.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.AssertException;

public class GClassLoader extends URLClassLoader {

	public GClassLoader(List<File> moduleDirs) {
		super(findUrls(moduleDirs), ClassLoader.getSystemClassLoader());
	}

	private static URL[] findUrls(List<File> moduleDirs) {
		List<URL> urls = new ArrayList<>();

		for (File moduleDir : moduleDirs) {
			File binDir = new File(moduleDir, "bin/main");
			if (binDir.exists()) {
				addFileURL(urls, binDir);
			}
			addModuleJars(urls, new File(moduleDir, "lib"));
		}

		return urls.toArray(new URL[urls.size()]);
	}

	private static void addFileURL(List<URL> urls, File binDir) {
		try {
			urls.add(binDir.toURI().toURL());
		}
		catch (MalformedURLException e) {
			throw new AssertException("Can't happen since we checked that it exists.");
		}
	}

	private static void addModuleJars(List<URL> urls, File libDir) {
		if (!libDir.isDirectory()) {
			return;
		}
		File[] listFiles = libDir.listFiles();
		if (listFiles != null) {
			for (File jarFile : listFiles) {
				if (isJarFile(jarFile)) {
					addFileURL(urls, jarFile);
				}
			}
		}
	}

	private static boolean isJarFile(File jarFile) {
		return jarFile.exists() && jarFile.getName().endsWith(".jar");
	}

}
