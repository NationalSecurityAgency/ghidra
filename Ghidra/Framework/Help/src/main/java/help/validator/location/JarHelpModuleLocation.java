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
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;

import javax.help.HelpSet;
import javax.help.HelpSetException;

import docking.help.GHelpSet;
import ghidra.util.exception.AssertException;
import help.validator.model.GhidraTOCFile;

public class JarHelpModuleLocation extends HelpModuleLocation {

	private static Map<String, String> env = new HashMap<String, String>();
	static {
		env.put("create", "false");
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

	public JarHelpModuleLocation(File file) {
		super(getOrCreateJarFS(file).getPath("/help"));
	}

	@Override
	public boolean isHelpInputSource() {
		return false;
	}

	@Override
	public HelpSet loadHelpSet() {
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(helpDir, "*_HelpSet.hs");) {
			for (Path path : ds) {
				return new GHelpSet(null, path.toUri().toURL());
			}
		}
		catch (IOException e) {
			throw new AssertException("No _HelpSet.hs file found for help directory: " + helpDir);
		}
		catch (HelpSetException e) {
			throw new AssertException("Error loading help set for " + helpDir);
		}

		throw new AssertException("Pre-built help jar file is missing it's help set: " + helpDir);
	}

	@Override
	public GhidraTOCFile loadSourceTOCFile() {
		return null; // jar files have only generated content, not the source TOC file
	}
}
