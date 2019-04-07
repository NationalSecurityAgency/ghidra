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
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Conv;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing Microsoft MAP files.
 */
public class MapLoader extends AbstractLibrarySupportLoader {
	public final static String MAP_NAME = "Program Mapfile (MAP)";

	public static final String NO_MAGIC = "0";

	private List<MapExport> parseExports(ByteProvider provider) throws IOException {
		ArrayList<MapExport> list = new ArrayList<>();
		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(provider.getInputStream(0)))) {
			boolean hasExports = false;

			while (true) {
				String line = reader.readLine();
				if (line == null) {
					break;
				}
				if (line.startsWith(";")) {// comment
					continue;
				}
				else if (line.indexOf("Publics by Value") != -1) {
					hasExports = true;
				}
				else if (hasExports) {
					MapExport exp = new MapExport(line);
					list.add(exp);
				}
			}
		}
		return list;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.getName() != null && provider.getName().toLowerCase().endsWith(".map") &&
			!parseExports(provider).isEmpty()) {
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
			MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log) throws IOException {

		if (!prog.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			throw new IOException("Program must be a " + PeLoader.PE_NAME);
		}

		SymbolTable symtab = prog.getSymbolTable();
		for (MapExport exp : parseExports(provider)) {
			long addr = exp.addr & Conv.INT_MASK;
			Address address = prog.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
			try {
				Symbol name = symtab.createLabel(address, exp.name, SourceType.IMPORTED);
				name.setPrimary();
			}
			catch (InvalidInputException e) {
				log.appendMsg(e.getMessage());
			}
		}
	}

	private class MapExport {
		String offset;
		String name;
		int addr;
		String type;

		MapExport(String exportLine) {
			StringTokenizer nizer = new StringTokenizer(exportLine, " ");

			offset = nizer.nextToken();
			name = nizer.nextToken();
			addr = Integer.parseInt(nizer.nextToken());
			type = nizer.nextToken();
		}
	}

	@Override
	public String getName() {
		return MAP_NAME;
	}
}
