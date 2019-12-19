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
package ghidra.app.util.opinion;

import java.io.File;
import java.io.IOException;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.datastruct.FixedSizeHashMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LibraryLookupTable {

	static final String EXPORTS_FILE_EXTENSION = ".exports";
	static final String ORDINAL_MAPPING_FILE_EXTENSION = ".ord";

	private static final int MAX_CACHE_ITEMS = 10;

	private static Map<String, LibrarySymbolTable> cacheMap =
		new FixedSizeHashMap<>(MAX_CACHE_ITEMS, MAX_CACHE_ITEMS);

	private static List<ResourceFile> filesToDeleteList = new ArrayList<>();

	private static String getMemorySizePath(int size) {
		return (size <= 32) ? "win32" : "win64";
	}

	private static ResourceFile createUserResourceDir(int size) {
		File symbols = new File(Application.getUserSettingsDirectory(), "symbols");
		if (!(symbols.exists() && symbols.isDirectory())) {
			if (!symbols.mkdir()) {
				Msg.error(LibraryLookupTable.class,
					"couldn't create symbols directory in user's home directory");
				return null;
			}
		}
		File win = new File(symbols, getMemorySizePath(size));
		if (!(win.exists() && win.isDirectory())) {
			if (!win.mkdir()) {
				Msg.error(LibraryLookupTable.class,
					"couldn't create symbols/win directory in user's home directory");
				return null;
			}
		}
		return new ResourceFile(win);
	}

	private static ResourceFile getSystemResourceDir(int size) {
		try {
			return ghidra.framework.Application.getModuleDataSubDirectory(
				"symbols/" + getMemorySizePath(size));
		}
		catch (Exception e) {
			Msg.error(LibraryLookupTable.class,
				"couldn't find symbols/win directory in module data directory", e);
		}
		return null;
	}

	synchronized static void getFiles(String dllname, int size, Set<String> unresolvedLibs,
			Set<String> resolvedLibs) {
		if (unresolvedLibs.contains(dllname) || resolvedLibs.contains(dllname)) {
			return;
		}
		ResourceFile file = getExistingExportsFile(dllname, size);
		if (file == null) {
			unresolvedLibs.add(dllname);
			return;
		}

		//check if it should be re-created...
		long lastExport = file.lastModified();
		ResourceFile defFile = getExistingOrdinalFile(dllname, size);
		long lastDef = defFile.lastModified();
		if (lastDef > lastExport) {
			unresolvedLibs.add(dllname);
		}

		LibrarySymbolTable table = LibraryLookupTable.getSymbolTable(dllname, size);
		if (table == null) {
			unresolvedLibs.add(dllname);
			return;
		}
		resolvedLibs.add(dllname);

		List<String> forwards = table.getForwards();
		for (String forward : forwards) {
			getFiles(forward, size, unresolvedLibs, resolvedLibs);
		}
	}

	synchronized static void cleanup() {
		for (ResourceFile file : filesToDeleteList) {
			file.delete();
		}
		filesToDeleteList.clear();
	}

	public synchronized static ResourceFile createFile(Program program, boolean overwrite,
			TaskMonitor monitor) throws IOException, CancelledException {
		return createFile(program, overwrite, false, monitor);
	}

	public synchronized static ResourceFile createFile(Program program, boolean overwrite,
			boolean inSystem, TaskMonitor monitor) throws IOException, CancelledException {
		ResourceFile file = null;
		int size = program.getLanguage().getLanguageDescription().getSize();

		if (inSystem) {
			file = getNewSystemExportsFile(new File(program.getExecutablePath()).getName(), size);
		}
		else {
			file = getNewExportsFile(program.getName(), size);
		}
		if (file.exists() && !overwrite) {
			return file;
		}

		monitor.setMessage("[" + program.getName() + "]: creating symbol file...");
		LibrarySymbolTable symTab = new LibrarySymbolTable(program, monitor);
		cacheMap.put(symTab.getCacheKey(), symTab);

		Options props = program.getOptions(Program.PROGRAM_INFO);
		String company = props.getString("CompanyName", "");
		String version = props.getString("FileVersion", "");

		boolean save = company != null && company.toLowerCase().indexOf("microsoft") >= 0;
		if (!save) {
			filesToDeleteList.add(file);
		}
		else {
			symTab.setVersion(version);
		}

		// apply any name definition files
		ResourceFile existingDefFile = getExistingOrdinalFile(program.getName(), size);
		if (existingDefFile != null) {
			symTab.applyOrdinalFile(existingDefFile, false);
		}

		monitor.checkCanceled();

		File f = file.getFile(true);
		if (f == null) {
			Msg.warn(LibraryLookupTable.class, "Can't write to installation directory");
		}
		else {
			symTab.write(f, new File(program.getExecutablePath()), version);
		}

		return file;
	}

	/**
	 * Get the symbol table associated with the DLL name.  If not previously
	 * generated for the given dllName, it will be constructed from a .exports
	 * file found within the 'symbols' resource area.  If a .exports file
	 * is not found a similarly named .ord file will be used if found.  The 
	 * .exports file is a Ghidra XML file formatted file, while the .ord file
	 * is produced with the Visual Studio DUMPBIN /EXPORTS command.  The default 
	 * resource area is located within the directory
	 * <pre>
	 *   Ghidra/Features/Base/data/symbols/[win32|win64]
	 * </pre>
	 * Alternatively, a user specific resource directory may be used which 
	 * is located at 
	 * <pre>
	 *   &lt;USER_HOME&gt;/.ghidra/&lt;.ghidraVersion&gt;/symbols/[win32|win64]
	 * </pre>
	 * The cacheMap is a static cache which always returns the same
	 * instance for a given DLL name.
	 * 
	 * @param dllName The DLL name (including extension)
	 * @param size The architecture size of the DLL (e.g., 32 or 64).
	 * @return LibrarySymbolTable associated with dllName
	 */
	synchronized static LibrarySymbolTable getSymbolTable(String dllName, int size) {
		String cacheKey = LibrarySymbolTable.getCacheKey(dllName, size);
		LibrarySymbolTable symTab = cacheMap.get(cacheKey);
		if (symTab != null) {
			return symTab;
		}

		// look in resources of pre-parsed .dll's
		ResourceFile file = getExistingExportsFile(dllName, size);
		if (file != null) {
			try {
				symTab = new LibrarySymbolTable(file, size);
				cacheMap.put(symTab.getCacheKey(), symTab);
				return symTab;
			}
			catch (IOException e) {
				Msg.error(LibraryLookupTable.class, "Error reading " + file + ": " + e.getMessage(),
					e);
			}
		}

		ResourceFile existingOrdinalFile = getExistingOrdinalFile(dllName, size);
		if (existingOrdinalFile != null) {
			symTab = new LibrarySymbolTable(dllName, size);
			symTab.applyOrdinalFile(existingOrdinalFile, true);
			cacheMap.put(symTab.getCacheKey(), symTab);
			return symTab;
		}

		return null;
	}

	synchronized static boolean libraryLookupTableFileExists(String dllname, int size) {
		return getExistingExportsFile(dllname, size) != null;
	}

	synchronized static ResourceFile getExistingExportsFile(String dllName, int size) {
		return getExistingExtensionedFile(dllName, EXPORTS_FILE_EXTENSION, size);
	}

	synchronized static ResourceFile getNewExportsFile(String dllName, int size) {
		return getNewExtensionedFile(dllName, EXPORTS_FILE_EXTENSION, size);
	}

	private static ResourceFile getNewSystemExportsFile(String name, int size) {
		return getNewSystemExtensionedFile(name, EXPORTS_FILE_EXTENSION, size);
	}

	synchronized static ResourceFile getExistingOrdinalFile(String dllName, int size) {
		return getExistingExtensionedFile(dllName, ORDINAL_MAPPING_FILE_EXTENSION, size);
	}

	synchronized static boolean hasFileAndPathAndTimeStampMatch(File libraryFile, int size) {
		try {
			return LibrarySymbolTable.hasFileAndPathAndTimeStampMatch(
				getExistingExportsFile(libraryFile.getName(), size), libraryFile);
		}
		catch (Exception e) {
			Msg.debug(LibraryLookupTable.class,
				"got exception looking for .exports file (or parsing, etc.)");
		}
		return false;
	}

	static String stripPossibleExtensionFromFilename(String filename) {
		int dotPos = filename.lastIndexOf('.');
		if (dotPos > 0) {
			filename = filename.substring(0, dotPos).toLowerCase();
		}
		return filename;
	}

	synchronized static ResourceFile getExtensionedFile(ResourceFile baseDir, String dllName,
			String extension) {
		return new ResourceFile(baseDir, dllName + extension);
	}

	synchronized static ResourceFile getStrippedExtensionedFile(ResourceFile baseDir,
			String dllName, String extension) {
		String stripName = stripPossibleExtensionFromFilename(dllName).toLowerCase();
		return new ResourceFile(baseDir, stripName + extension);
	}

	synchronized static ResourceFile getExistingExtensionedFile(String dllName, String extension,
			int size) {

		String strippedExtensionFilename =
			stripPossibleExtensionFromFilename(dllName).toLowerCase() + extension;
		String extensionFilename = dllName.toLowerCase() + extension;

		ResourceFile[] userFiles = createUserResourceDir(size).listFiles();
		ResourceFile[] systemFiles = getSystemResourceDir(size).listFiles();

		for (ResourceFile currFile : userFiles) {
			String currFileName = currFile.getName();

			if (currFileName.equalsIgnoreCase(strippedExtensionFilename) ||
				currFileName.equalsIgnoreCase(extensionFilename)) {
				return currFile;
			}
		}

		for (ResourceFile currFile : systemFiles) {
			String currFileName = currFile.getName();

			if (currFileName.equalsIgnoreCase(strippedExtensionFilename) ||
				currFileName.equalsIgnoreCase(extensionFilename)) {
				return currFile;
			}
		}

		return null;
	}

	synchronized static ResourceFile getNewExtensionedFile(String dllName, String extension,
			int size) {
		return getStrippedExtensionedFile(createUserResourceDir(size), dllName, extension);
	}

	synchronized static ResourceFile getNewSystemExtensionedFile(String dllName, String extension,
			int size) {
		return getStrippedExtensionedFile(getSystemResourceDir(size), dllName, extension);
	}
}
