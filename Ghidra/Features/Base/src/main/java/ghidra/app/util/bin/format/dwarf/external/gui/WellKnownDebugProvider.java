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
package ghidra.app.util.bin.format.dwarf.external.gui;

import java.io.IOException;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

/**
 * Represents a debug file search location that has been pre-provided by a Ghidra config file.
 *  
 * @param location url string 
 * @param locationCategory grouping criteria
 * @param warning string
 * @param fileOrigin file name that contained this info
 */
public record WellKnownDebugProvider(String location, String locationCategory,
		String warning, String fileOrigin) {

	/**
	 * Loads information about wellknown debuginfod servers from any matching file found in the 
	 * application and returns a list of entries.
	 * 
	 * @param fileExt extension of the url files to find 
	 * @return list of {@link WellKnownDebugProvider} elements
	 */
	public static List<WellKnownDebugProvider> loadAll(String fileExt) {
		List<ResourceFile> files = Application.findFilesByExtensionInApplication(fileExt);
		Set<WellKnownDebugProvider> seenProviders = new HashSet<>();
		List<WellKnownDebugProvider> results = new ArrayList<>();
		for (ResourceFile file : files) {
			try {
				List<String> lines = FileUtilities.getLines(file);
				for (String line : lines) {
					// format: location_category|location_string|warning_string
					// example: "Internet|https://msdl.microsoft.com/download/symbols|Warning: be careful!"
					String[] fields = line.split("\\|");
					if (fields.length > 1) {
						WellKnownDebugProvider provider = new WellKnownDebugProvider(fields[1],
							fields[0], fields.length > 2 ? fields[2] : null, file.getName());
						if (seenProviders.add(provider)) {
							results.add(provider);
						}
					}
				}
			}
			catch (IOException e) {
				Msg.warn(WellKnownDebugProvider.class, "Unable to read file: " + file);
			}
		}
		return results;
	}

}
