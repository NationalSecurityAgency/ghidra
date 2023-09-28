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
package help.validator.location;

import java.io.File;
import java.io.IOException;
import java.net.*;
import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;

import javax.help.HelpSet;
import javax.help.HelpSetException;

import ghidra.util.exception.AssertException;
import help.GHelpSet;
import help.validator.model.GhidraTOCFile;

public class JarHelpModuleLocation extends HelpModuleLocation {

	private static Map<String, String> env = new HashMap<>();
	static {
		env.put("create", "false");
	}

	public static JarHelpModuleLocation fromFile(File jar) {
		FileSystem fs = getOrCreateJarFS(jar);
		Path helpRootPath = fs.getPath("/help");
		if (!Files.exists(helpRootPath)) {
			return null;
		}

		Path topicsPath = helpRootPath.resolve("topics");

		if (!Files.exists(topicsPath)) {
			// all help locations must have a topics directory; we can get here if the jar contains
			// a package with the name 'help'
			return null;
		}

		return new JarHelpModuleLocation(jar, helpRootPath);
	}

	private static FileSystem getOrCreateJarFS(File jar) {
		URI jarURI;
		try {
			jarURI = new URI("jar:file://" + jar.toURI().getRawPath());
		}
		catch (URISyntaxException e) {
			throw new RuntimeException("Internal error", e);
		}
		try {
			return FileSystems.getFileSystem(jarURI);
		}
		catch (FileSystemNotFoundException e) {
			try {
				return FileSystems.newFileSystem(jarURI, env);
			}
			catch (IOException e1) {
				throw new RuntimeException("Unexpected error building help", e1);
			}
		}
	}

	private JarHelpModuleLocation(File jar, Path path) {
		super(path);
	}

	@Override
	public boolean isHelpInputSource() {
		return false;
	}

	@Override
	public HelpSet loadHelpSet() {

		// Our convention is to name the help set after the module
		File jarFile = getJarFile();
		String moduleName = getModuleName(jarFile);
		Path hsPath = helpDir.resolve(moduleName + "_HelpSet.hs");
		try {
			return new GHelpSet(null, hsPath.toUri().toURL());
		}
		catch (MalformedURLException | HelpSetException e) {
			throw new AssertException(
				"Pre-built help jar file is missing it's help set: " + helpDir, e);
		}
	}

	private File getJarFile() {

		// format: jar:file:///.../Ghidra/Features/<module>/build/libs/<module>.jar!/help
		String uriString = helpDir.toUri().toString();
		int start = uriString.indexOf("file:/");
		String chopped = uriString.substring(start);
		int end = chopped.indexOf("!");
		chopped = chopped.substring(0, end);
		return new File(chopped);
	}

	private String getModuleName(File jarFile) {
		String name = jarFile.getName();
		int dotIndex = name.indexOf("-help.jar"); // dev mode
		if (dotIndex == -1) {
			dotIndex = name.indexOf(".jar"); // production mode
		}
		return name.substring(0, dotIndex);
	}

	@Override
	public Path getHelpModuleLocation() {
		// start format: jar:file:///.../Ghidra/Features/Base/build/libs/Base.jar!/help

		// format: file:///.../Ghidra/Features/<module>/build/libs/<module>.jar
		File jarFile = getJarFile();
		String moduleName = getModuleName(jarFile);
		String fullPath = jarFile.getPath();
		int moduleNameStart = fullPath.indexOf(moduleName);
		int end = moduleNameStart + moduleName.length();
		String moduleString = fullPath.substring(0, end);
		Path modulePath = Paths.get(moduleString);
		return modulePath;
	}

	@Override
	public GhidraTOCFile loadSourceTOCFile() {
		return null; // jar files have only generated content, not the source TOC file
	}
}
