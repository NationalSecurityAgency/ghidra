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
package ghidra.program.util;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class ELFExternalSymbolResolver {

	/**
	 * Links unresolved symbols to the first symbol found in the (ordered) linked
	 * libraries (saved in the program's properties as "ELF Required Library [nn]").
	 * <p>
	 * The ordering and precedence logic is ELF specific though no ELF binary formats
	 * are parsed or required.
	 * <p>
	 * The program's external libraries need to already be populated with paths to
	 * already existing / imported libraries.
	 * <p>
	 *
	 * @param program ELF {@link Program} to fix.
	 * @param saveIfModified boolean flag, if true the program will be saved if there was a
	 * modification.
	 * @param messageLog {@link MessageLog} to write info message to.
	 * @param monitor {@link TaskMonitor} to watch for cancel and update with progress.
	 * @throws CancelledException if user cancels
	 * @throws IOException if error reading
	 */
	public static void fixUnresolvedExternalSymbols(Program program, boolean saveIfModified,
			MessageLog messageLog, TaskMonitor monitor) throws CancelledException, IOException {
		ProjectData projectData = program.getDomainFile().getParent().getProjectData();

		Collection<Long> unresolvedExternalFunctionIds = getUnresolvedExternalFunctionIds(program);
		if (unresolvedExternalFunctionIds.size() == 0) {
			return;
		}

		List<Library> libSearchList = getLibrarySearchList(program);
		if (libSearchList.isEmpty()) {
			return;
		}

		int transactionID = program.startTransaction("Resolve External Symbols");
		try {

			messageLog.appendMsg("----- [" + program.getName() + "] Resolve " +
				unresolvedExternalFunctionIds.size() + " external symbols -----");

			for (Library extLibrary : libSearchList) {
				monitor.checkCanceled();
				String libName = extLibrary.getName();
				String libPath = extLibrary.getAssociatedProgramPath();
				if (libPath == null) {
					continue;
				}

				DomainFile libDomainFile = projectData.getFile(libPath);
				if (libDomainFile == null) {
					messageLog.appendMsg("Referenced external program not found: " + libPath);
					continue;
				}

				Object consumer = new Object();
				DomainObject libDomainObject = null;
				try {
					libDomainObject =
						libDomainFile.getDomainObject(consumer, false, false, monitor);
					if (!(libDomainObject instanceof Program)) {
						messageLog.appendMsg(
							"Referenced external program is not a program: " + libPath);
						continue;
					}
					monitor.setMessage("Resolving symbols published by library " + libName);
					resolveSymbolsToLibrary(program, unresolvedExternalFunctionIds, extLibrary,
						(Program) libDomainObject, messageLog, monitor);
				}
				catch (IOException e) {
					// failed to open library
					messageLog.appendMsg("Failed to open library dependency project file: " +
						libDomainFile.getPathname());
				}
				catch (VersionException e) {
					messageLog.appendMsg(
						"Referenced external program requires updgrade, unable to consider symbols: " +
							libPath);
				}
				finally {
					if (libDomainObject != null) {
						libDomainObject.release(consumer);
					}
				}
			}
			messageLog.appendMsg("Unresolved external symbols which remain: " +
				unresolvedExternalFunctionIds.size());
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		if (saveIfModified && program.canSave() && program.isChanged()) {
			program.save("ExternalSymbolResolver", monitor);
		}
	}

	private static void resolveSymbolsToLibrary(Program program,
			Collection<Long> unresolvedExternalFunctionIds, Library extLibrary, Program libProgram,
			MessageLog messageLog, TaskMonitor monitor) throws CancelledException {
		int libResolvedCount = 0;
		ExternalManager externalManager = program.getExternalManager();
		SymbolTable symbolTable = program.getSymbolTable();

		Iterator<Long> idIterator = unresolvedExternalFunctionIds.iterator();
		while (idIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol s = symbolTable.getSymbol(idIterator.next());
			if (s == null || !s.isExternal() || s.getSymbolType() != SymbolType.FUNCTION) {
				Msg.error(ELFExternalSymbolResolver.class,
					"Concurrent modification of symbol table while resolving external symbols");
				idIterator.remove();
				continue;
			}

			ExternalLocation extLoc = externalManager.getExternalLocation(s);
			if (s.getSource() == SourceType.DEFAULT ||
				!isLocationContainedInLibrary(libProgram, extLoc)) {
				continue;
			}
			try {
				s.setNamespace(extLibrary);
				idIterator.remove();
				libResolvedCount++;
				Msg.debug(ELFExternalSymbolResolver.class, "External symbol " + extLoc.getLabel() +
					" resolved to " + extLibrary.getName());
			}
			catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				Msg.error(ELFExternalSymbolResolver.class,
					"Error setting external symbol namespace for " + extLoc.getLabel(), e);
			}
		}
		messageLog.appendMsg(
			"Resolved " + libResolvedCount + " symbols to library " + extLibrary.getName());
	}

	private static boolean isLocationContainedInLibrary(Program libProgram,
			ExternalLocation extLoc) {

		String name = extLoc.getOriginalImportedName();
		if (name == null) {
			name = extLoc.getLabel();
		}
		for (Symbol s : libProgram.getSymbolTable().getLabelOrFunctionSymbols(name, null)) {
			if (s.isExternalEntryPoint()) {
				return true;
			}
		}
		return false;
	}

	private static Collection<Long> getUnresolvedExternalFunctionIds(Program program) {
		List<Long> symbolIds = new ArrayList<>();
		ExternalManager externalManager = program.getExternalManager();
		Library library = externalManager.getExternalLibrary(Library.UNKNOWN);
		if (library != null) {
			for (Symbol s : program.getSymbolTable().getSymbols(library)) {
				if (s.getSymbolType() == SymbolType.FUNCTION) {
					symbolIds.add(s.getID());
				}
			}
		}
		return symbolIds;
	}

	private static Collection<String> getOrderedLibraryNamesNeeded(Program program) {
		TreeMap<Integer, String> orderLibraryMap = new TreeMap<>();
		Options options = program.getOptions(Program.PROGRAM_INFO);
		//List<String> sortedOptionNames = new ArrayList<>();
		for (String optionName : options.getOptionNames()) {
			if (!optionName.startsWith(ElfLoader.ELF_REQUIRED_LIBRARY_PROPERTY_PREFIX) ||
				!optionName.endsWith("]")) {
				continue;
			}
			String libName = options.getString(optionName, null);
			if (libName == null) {
				continue;
			}
			String indexStr =
				optionName.substring(ElfLoader.ELF_REQUIRED_LIBRARY_PROPERTY_PREFIX.length(),
					optionName.length() - 1).trim();
			try {
				orderLibraryMap.put(Integer.parseInt(indexStr), libName.trim());
			}
			catch (NumberFormatException e) {
				Msg.error(ELFExternalSymbolResolver.class,
					"Program contains invalid property: " + optionName);
			}
		}
		return orderLibraryMap.values();
	}

	private static List<Library> getLibrarySearchList(Program program) {
		List<Library> result = new ArrayList<>();
		ExternalManager externalManager = program.getExternalManager();
		for (String libName : getOrderedLibraryNamesNeeded(program)) {
			Library lib = externalManager.getExternalLibrary(libName);
			if (lib != null) {
				result.add(lib);
			}
		}
		return result;
	}
}
