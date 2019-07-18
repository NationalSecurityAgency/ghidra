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
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing Microsoft MAP files.
 * <p>
 * Sample .map file section we parse to extract symbol information:
 * <pre>
 *   ...
 *   ...
 *   ...
 *
 *   Address         Publics by Value              Rva+Base               Lib:Object
 *   
 *  0000:00000000       ___safe_se_handler_table   0000000000000000     &lt;absolute&gt;
 *  0000:00000000       ___safe_se_handler_count   0000000000000000     &lt;absolute&gt;
 *  0000:00000000       __ImageBase                0000000140000000     &lt;linker-defined&gt;
 *  0001:00000040       foo                        0000000140001040 f   foo.obj
 *  0001:000000c0       bar                        00000001400010c0 f   foo.obj
 *  
 *  ...
 *  ...
 *  ...
 *  </pre>
 */
public class MapLoader extends AbstractLibrarySupportLoader {
	public final static String MAP_NAME = "Program Mapfile (MAP)";

	public static final String NO_MAGIC = "0";

	/**
	 * Parses exported symbol information from the MAP file represented by the given provider.
	 * 
	 * @param provider The bytes representing a MAP file
	 * @param log An optional log to write to (could be null)
	 * @return A {@link List} of {@link MapExport}s representing exported symbol information
	 * @throws IOException If there was a problem parsing
	 */
	private List<MapExport> parseExports(ByteProvider provider, MessageLog log) throws IOException {
		ArrayList<MapExport> list = new ArrayList<>();
		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(provider.getInputStream(0)))) {
			boolean hasExports = false;

			String line;
			int lineNumber = 0;
			while ((line = reader.readLine()) != null) {
				lineNumber++;
				line = line.trim();
				if (line.startsWith(";")) {// comment
					continue;
				}
				if (hasExports) {
					if (!line.isEmpty()) {
						try {
							list.add(MapExport.parse(line, lineNumber));
						}
						catch (ParseException e) {
							if (log != null) {
								log.appendMsg(e.getMessage());
							}
						}
					}
					else if (!list.isEmpty()) {
						break;
					}
				}
				else if (line.indexOf("Publics by Value") != -1) {
					hasExports = true;
				}
			}
		}
		return list;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.getName() != null && provider.getName().toLowerCase().endsWith(".map") &&
			!parseExports(provider, null).isEmpty()) {
			List<QueryResult> results = QueryOpinionService.query(getName(), NO_MAGIC, null);
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, 0, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program prog,
			TaskMonitor monitor, MessageLog log) throws IOException {

		if (!prog.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			throw new IOException("Program must be a " + PeLoader.PE_NAME);
		}

		SymbolTable symtab = prog.getSymbolTable();
		AddressSpace space = prog.getAddressFactory().getDefaultAddressSpace();
		List<MapExport> exports = parseExports(provider, log);
		int successCount = 0;
		for (MapExport exp : exports) {
			try {
				symtab.createLabel(space.getAddress(exp.addr), exp.name,
					SourceType.IMPORTED).setPrimary();
				successCount++;
			}
			catch (InvalidInputException e) {
				log.appendMsg(e.getMessage());
			}
		}
		log.appendMsg("Added " + successCount + " symbols.");
	}

	/**
	 * Represents a single exported symbol from a MAP file. 
	 */
	private static class MapExport {
		private String name;
		private long addr;

		private MapExport(String name, long addr) {
			this.name = name;
			this.addr = addr;
		}

		/**
		 * Parses a single exported symbol from the given MAP file line.
		 * 
		 * @param exportLine The line to parse
		 * @param lineNumber The line number of the line to parse
		 * @return A {@link MapExport} object representing the parsed exported symbol info
		 * @throws ParseException If there was a problem parsing the line
		 */
		public static MapExport parse(String exportLine, int lineNumber) throws ParseException {
			String name;
			long addr;
			StringTokenizer st = new StringTokenizer(exportLine);
			
			// Ignore first field
			if (st.hasMoreTokens()) {
				st.nextToken();
			}
			else {
				throw new ParseException("Line " + lineNumber + ": Failed to parse first field",
					lineNumber);
			}
			
			// Parse name field
			if (st.hasMoreTokens()) {
				name = st.nextToken();
			}
			else {
				throw new ParseException(
					"Line " + lineNumber + ": Failed to parse second (name) field", lineNumber);
			}

			// Get addr field
			if (st.hasMoreTokens()) {
				try {
					addr = Long.parseLong(st.nextToken(), 16);
				}
				catch (NumberFormatException e) {
					throw new ParseException(
						"Line " + lineNumber + ": Failed to parse third (addr) field", lineNumber);
				}
			}
			else {
				throw new ParseException(
					"Line " + lineNumber + ": Failed to parse third (addr) field", lineNumber);
			}
			
			return new MapExport(name, addr);
		}
	}

	@Override
	public String getName() {
		return MAP_NAME;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}
}
