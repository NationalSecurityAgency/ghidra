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
package ghidra.file.formats.sevenzip;

import java.util.*;
import java.util.stream.Collectors;

import java.io.*;

import ghidra.framework.Application;
import net.sf.sevenzipjbinding.SevenZip;
import net.sf.sevenzipjbinding.SevenZipNativeInitializationException;

/**
 *
 *  Custom logic to initialize Sevenzip's native libraries that have been placed into
 *  Ghidra's module data directory by a gradle build task (see extractSevenZipNativeLibs in build.gradle).
 *  <p>
 *  It is necessary to use this method instead of Sevenzip.initSevenZipFromPlatformJAR() 
 *  because it has a logic error when extracting the native libraries and always overwrites 
 *  the existing libraries, causing other java processes that have already loaded those 
 *  libraries to core-dump.
 *  <p>
 *  See https://github.com/borisbrodski/sevenzipjbinding/issues/50
 *  <p>
 *  This class (and the tasks in build.gradle) can be removed if/when upstream
 *  fixes the problem with native libraries always being over-written during initialization (and
 *  thereby causing earlier-loaded java vms to core dump) and also does not produce errors when
 *  multiple vms are simultaneously started. 
 */
public class SevenZipCustomInitializer {

	/**
	 * Call this before using any SevenzipJBinding classes.  Calling multiple times
	 * is okay.
	 * <p>
	 * Most likely cause of failure is running on an unsupported platform.
	 * <p>
	 * 
	 * @throws SevenZipNativeInitializationException
	 */
	public static synchronized void initSevenZip() throws SevenZipNativeInitializationException {
		if (SevenZip.isInitializedSuccessfully()) {
			return;
		}

		try {
			String platform = SevenZip.getPlatformBestMatch();

			// This depends on the sevenzip native libraries being extracted from the sevenzip jar
			// and being placed in the data/sevenzipnativelibs/ directory by a gradle task.
			// Sevenzip's platform designator will be used to pick the appropriate native library,
			// for example "/data/sevenzipnativelibs/Linux-amd64/lib7-Zip-JBinding.so".
			File libDir = Application.getModuleDataSubDirectory("sevenzipnativelibs/" + platform)
					.getFile(false);

			Properties properties = loadProperties(platform);

			// libName -> hash.  hash not used at the moment
			Map<String, String> nativeLibraryInfo = getNativeLibraryInfo(properties);
			List<File> libFiles = nativeLibraryInfo.keySet()
					.stream()
					.map(libName -> new File(libDir, libName))
					.collect(Collectors.toList());
			loadNativeLibraries(libFiles);
			SevenZip.initLoadedLibraries();
		}
		catch (IOException e) {
			throw new SevenZipNativeInitializationException("Error initializing SevenzipJbinding",
				e);
		}
	}

	private static Properties loadProperties(String platform)
			throws SevenZipNativeInitializationException, IOException {
		// prop file contains lib.##.name and lib.##.hash values
		String propFilename = "/" + platform + "/sevenzipjbinding-lib.properties";
		try (InputStream propFileStream = SevenZip.class.getResourceAsStream(propFilename)) {
			if (propFileStream == null) {
				throw new IOException("Error loading property file stream " + propFilename);
			}

			Properties properties = new Properties();
			properties.load(propFileStream);
			return properties;
		}
	}

	private static Map<String, String> getNativeLibraryInfo(Properties properties)
			throws IOException {
		// LinkedHashMap to preserve order
		LinkedHashMap<String, String> libraryInfo = new LinkedHashMap<>();
		int libNum = 1;
		String libName;
		while ((libName = properties.getProperty(String.format("lib.%d.name", libNum))) != null) {
			String libHash = properties.getProperty(String.format("lib.%d.hash", libNum));
			if (libHash == null) {
				throw new IOException(
					"Missing library hash value in property file for library lib." + libNum +
						".name=" + libName);
			}
			libraryInfo.put(libName, libHash);
			libNum++;
		}
		if (libraryInfo.isEmpty()) {
			throw new IOException("Missing library hash values in property file");
		}
		return libraryInfo;
	}

	private static void loadNativeLibraries(List<File> libFiles)
			throws SevenZipNativeInitializationException {
		// Load native libraries in reverse order (per the logic in upstream's initialization code)
		for (int i = libFiles.size() - 1; i >= 0; i--) {
			File libFile = libFiles.get(i);
			try {
				System.load(libFile.getPath());
			}
			catch (Throwable t) {
				throw new SevenZipNativeInitializationException(
					"Error loading native library: " + libFile, t);
			}
		}
	}
}
