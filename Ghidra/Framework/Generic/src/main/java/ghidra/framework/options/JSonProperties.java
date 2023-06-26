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
package ghidra.framework.options;

import java.io.*;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * A convenience class for creating a GProperties object from a file containing JSon data
 * generated from {@link GProperties#saveToJsonFile(File)}
 */
public class JSonProperties extends GProperties {

	public JSonProperties(File file) throws IOException {
		super(getJsonObject(file));

	}

	private static JsonObject getJsonObject(File file) throws IOException {
		try (Reader reader = new FileReader(file)) {
			return (JsonObject) JsonParser.parseReader(reader);
		}
	}

}
