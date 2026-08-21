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
package pdb.symbolserver.ui;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import pdb.symbolserver.SymbolServer;
import pdb.symbolserver.ui.LoadPdbDialog.StatusText;
import utilities.util.FileUtilities;

/**
 * Represents a well-known symbol server location.
 * <p>
 * See the PDB_SYMBOL_SERVER_URLS.pdburl file.
 * @param location url string 
 * @param locationCategory grouping criteria
 * @param warning string
 * @param fileOrigin file name that contained this info
 */
public record WellKnownSymbolServerLocation(String location, String locationCategory,
		String warning, String fileOrigin) {

	/**
	 * Loads all symbol server location files (*.pdburl) and returns a list of entries.
	 * 
	 * @return list of {@link WellKnownSymbolServerLocation} elements
	 */
	public static List<WellKnownSymbolServerLocation> loadAll() {
		List<ResourceFile> pdbUrlFiles = Application.findFilesByExtensionInApplication(".pdburl");

		List<WellKnownSymbolServerLocation> results = new ArrayList<>();
		for (ResourceFile file : pdbUrlFiles) {
			try {
				List<String> lines = FileUtilities.getLines(file);
				for (String line : lines) {
					// format: location_category|location_string|warning_string
					// example: "Internet|https://msdl.microsoft.com/download/symbols|Warning: be careful!"
					String[] fields = line.split("\\|");
					if (fields.length > 1) {
						results.add(new WellKnownSymbolServerLocation(fields[1], fields[0],
							fields.length > 2 ? fields[2] : null, file.getName()));
					}
				}
			}
			catch (IOException e) {
				Msg.warn(WellKnownSymbolServerLocation.class,
					"Unable to read pdburl file: " + file);
			}
		}
		return results;
	}

	/**
	 * Returns a formatted StatusText containing all the warnings published by any untrusted
	 * {@link WellKnownSymbolServerLocation} found in the list of symbolservers.
	 * 
	 * @param knownSymbolServers list
	 * @param symbolServers list
	 * @return StatusText
	 */
	public static StatusText getWarningsFor(List<WellKnownSymbolServerLocation> knownSymbolServers,
			List<SymbolServer> symbolServers) {
		Map<String, String> warningsByLocation = new HashMap<>();
		for (WellKnownSymbolServerLocation ssloc : knownSymbolServers) {
			if (ssloc.warning() != null && !ssloc.warning().isBlank()) {
				warningsByLocation.put(ssloc.location(), ssloc.warning());
			}
		}
		String warning = symbolServers.stream()
				.filter(symbolServer -> !symbolServer.isTrusted())
				.map(symbolServer -> warningsByLocation.get(symbolServer.getName()))
				.filter(Objects::nonNull)
				.distinct()
				.collect(Collectors.joining("<br>\n"));

		return !warning.isEmpty() ? new StatusText(warning, MessageType.WARNING, false) : null;
	}

}
