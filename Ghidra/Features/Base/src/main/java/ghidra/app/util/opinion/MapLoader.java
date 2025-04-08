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

import java.io.*;
import java.text.ParseException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing Microsoft MAP files.
 * <p>
 * Sample .map file section we parse to extract symbol information:
 * <pre>{@code
 *   ...
 *   ...
 *   ...
 *
 *   Address         Publics by Value              Rva+Base               Lib:Object
 *   
 *  0000:00000000       ___safe_se_handler_table   0000000000000000     <absolute>
 *  0000:00000000       ___safe_se_handler_count   0000000000000000     <absolute>
 *  0000:00000000       __ImageBase                0000000140000000     <linker-defined>
 *  0001:00000040       foo                        0000000140001040 f   foo.obj
 *  0001:000000c0       bar                        00000001400010c0 f   foo.obj
 *  
 *  ...
 *  ...
 * 
 *  Static symbols
 *
 *  0000:00000020       blah                       0000000140000010     foo.dll
 *  0001:00000020       stuff                      0000000140000020     bar.dll
 *
 *  ...
 *  ...
 *  ...
 *
 *  }</pre>
 */
public class MapLoader extends AbstractProgramWrapperLoader {
	public final static String MAP_NAME = "Program Mapfile (MAP)";

	public static final String NO_MAGIC = "0";

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (provider.getName() != null && provider.getName().toLowerCase().endsWith(".map")) {
			try {
				if (!parseMapFile(provider, TaskMonitor.DUMMY, null).isEmpty()) {
					List<QueryResult> results =
						QueryOpinionService.query(getName(), NO_MAGIC, null);
					for (QueryResult result : results) {
						loadSpecs.add(new LoadSpec(this, 0, result));
					}
					if (loadSpecs.isEmpty()) {
						loadSpecs.add(new LoadSpec(this, 0, true));
					}
				}

			}
			catch (CancelledException e) {
				// fall thru
			}
		}
		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program prog,
			TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {

		if (!prog.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			throw new IOException("Program must be a " + PeLoader.PE_NAME);
		}

		SymbolTable symtab = prog.getSymbolTable();
		AddressSpace space = prog.getAddressFactory().getDefaultAddressSpace();
		int successCount = 0;

		List<MapSymbol> symbols = parseMapFile(provider, monitor, log);
		monitor.initialize(symbols.size(), "Creating symbols...");
		for (MapSymbol symbol : symbols) {
			monitor.increment();
			try {
				Address addr = space.getAddress(symbol.addr);
				symtab.createLabel(addr, symbol.name, SourceType.IMPORTED).setPrimary();
				successCount++;
			}
			catch (InvalidInputException e) {
				log.appendMsg(
					"Error creating symbol '%s': %s".formatted(symbol.name, e.getMessage()));
			}
		}

		log.appendMsg("Added " + successCount + " symbols.");
	}

	@Override
	public String getName() {
		return MAP_NAME;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	/**
	 * Represents a MAP file symbol
	 * 
	 * @param name The symbol name
	 * @param addr The symbol address
	 */
	private record MapSymbol(String name, long addr) {}

	/**
	 * Parses symbol information from the MAP file represented by the given provider
	 * 
	 * @param provider The bytes representing a MAP file
	 * @param monitor The monitor
	 * @param log An optional log to write to (could be null)
	 * @return A {@link List} of {@link MapSymbol}s
	 * @throws IOException If there was a problem parsing
	 * @throws CancelledException if the user cancelled
	 */
	private List<MapSymbol> parseMapFile(ByteProvider provider, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {
		List<MapSymbol> symbols = new ArrayList<>();
		monitor.setMessage("Parsing MAP file...");
		monitor.setIndeterminate(true);
		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(provider.getInputStream(0)))) {
			String line;
			int lineNumber = 0;
			while ((line = reader.readLine()) != null) {
				monitor.checkCancelled();
				lineNumber++;
				line = line.trim();
				if (line.startsWith(";")) { // comment
					continue;
				}
				if (line.contains("Publics by Value")) {
					lineNumber = parseMapFileSection(reader, symbols, lineNumber, monitor, log);
				}
				else if (line.startsWith("Static symbols")) {
					lineNumber = parseMapFileSection(reader, symbols, lineNumber, monitor, log);
				}
			}
		}
		return symbols;
	}

	/**
	 * Parses symbol information from the given MAP file section
	 * 
	 * @param reader A {@link BufferedReader reader} pointing at the start of the MAP file section
	 * @param list A {@link List} to add parsed symbols to
	 * @param lineNumber The line number of the start of the MAP file section
	 * @param monitor A cancellable monitor
	 * @param log An optional log to write to (could be null)
	 * @return The line number after section parsing has finished
	 * @throws IOException If there was a problem parsing
	 * @throws CancelledException if the user cancelled
	 */
	private int parseMapFileSection(BufferedReader reader, List<MapSymbol> list, int lineNumber,
			TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {
		String line;
		boolean added = false;
		while ((line = reader.readLine()) != null) {
			monitor.checkCancelled();
			lineNumber++;
			line = line.trim();
			if (line.startsWith(";")) { // comment
				continue;
			}
			if (!line.isEmpty()) {
				try {
					list.add(parseMapSymbol(line, lineNumber));
					added = true;
				}
				catch (ParseException e) {
					if (log != null) {
						log.appendMsg(e.getMessage());
					}
				}
			}
			else if (added) {
				break;
			}
		}
		return lineNumber;
	}

	/**
	 * Parses a new {@link MapSymbol} from the given MAP file line
	 * 
	 * @param line The line to parse
	 * @param lineNumber The line number of the line to parse
	 * @return The parsed {@link MapSymbol}
	 * @throws ParseException if there was an issue parsing
	 */
	private MapSymbol parseMapSymbol(String line, int lineNumber) throws ParseException {
		String[] parts = line.split("\\s+", 4);
		if (parts.length < 3) {
			throw new ParseException(
				"Line %d has less than 3 fields (%d)".formatted(lineNumber, parts.length),
				lineNumber);
		}

		try {
			return new MapSymbol(parts[1], Long.parseLong(parts[2], 16));
		}
		catch (NumberFormatException e) {
			throw new ParseException(
				"Line %d address '%s' could not be converted to a number".formatted(lineNumber,
					parts[2]),
				lineNumber);
		}
	}
}
