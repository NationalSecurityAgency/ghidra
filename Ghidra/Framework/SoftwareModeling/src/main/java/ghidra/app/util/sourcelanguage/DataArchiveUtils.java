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
package ghidra.app.util.sourcelanguage;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import generic.jar.ResourceFile;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.sourcelanguage.SourceLanguageDataArchive.DataArchiveRule;
import ghidra.app.util.sourcelanguage.SourceLanguageSpecExtension.SpecExtensionRule;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class DataArchiveUtils {

	/**
	 * An entry from a spec extension JSON configuration file
	 * 
	 * @param processor The name of the processor (could be empty/null for wildcard)
	 * @param endian The processor endianness ("little" or "big") (could be empty/null for wildcard)
	 * @param size The processor size (i.e., "32, "64", etc) (could be empty/null for wildcard)
	 * @param variant The processor variant (could be empty/null for wildcard)
	 * @param formats The names of the binary file formats (could be empty/null for wildcard)
	 * @param file The file path (relative to the JSON configuration file) of the data archive file 
	 *   to add
	 */
	private record JsonEntry(String processor, String endian, String size, String variant,
			List<String> formats, String file) {}

	/**
	 * {@return a {@link List} of {@link SpecExtensionRule}s based on the given JSON configuration
	 * file}
	 * 
	 * @param jsonFile The JSON configuration file
	 * @param program The {@link Program}
	 * @param log The error log
	 * @param monitor The monitor
	 * @throws IOException if there was a problem reading the JSON configuration file or the
	 *   {@link SpecExtension} XML files it references
	 */
	public static List<DataArchiveRule> readDataArchiveJsonConfig(ResourceFile jsonFile,
			Program program, MessageLog log, TaskMonitor monitor) throws IOException {
		List<DataArchiveRule> ret = new ArrayList<>();
		try (JsonReader reader = new JsonReader(new InputStreamReader(jsonFile.getInputStream()))) {
			JsonEntry[] entries = new Gson().fromJson(reader, JsonEntry[].class);
			if (entries == null) {
				throw new EOFException(jsonFile + " was at end of file");
			}
			for (JsonEntry entry : entries) {
				if (entry == null) {
					continue;
				}
				ResourceFile file = new ResourceFile(jsonFile.getParentFile(), entry.file());
				ret.add(new DataArchiveRule(entry.processor(), entry.endian(), entry.size(),
					entry.variant(), entry.formats(), file));
			}
		}
		return ret;
	}
}
