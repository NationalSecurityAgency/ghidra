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

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

/**
 * Represents a well-known symbol server location.
 * <p>
 * See the PDB_SYMBOL_SERVER_URLS.pdburl file.
 */
class WellKnownSymbolServerLocation {
	private String locationCategory;
	private String location;
	private String warning;
	private String fileOrigin;

	WellKnownSymbolServerLocation(String location, String locationCategory, String warning,
			String fileOrigin) {
		this.location = location;
		this.locationCategory = locationCategory;
		this.warning = warning;
		this.fileOrigin = fileOrigin;
	}

	String getLocationCategory() {
		return locationCategory;
	}

	String getLocation() {
		return location;
	}

	String getWarning() {
		return warning;
	}

	String getFileOrigin() {
		return fileOrigin;
	}

	@Override
	public int hashCode() {
		return Objects.hash(location, locationCategory, warning);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		WellKnownSymbolServerLocation other = (WellKnownSymbolServerLocation) obj;
		return Objects.equals(location, other.location) &&
			Objects.equals(locationCategory, other.locationCategory) &&
			Objects.equals(warning, other.warning);
	}

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
				Msg.warn(WellKnownSymbolServerLocation.class, "Unable to read pdburl file: " + file);
			}
		}
		return results;
	}

}
