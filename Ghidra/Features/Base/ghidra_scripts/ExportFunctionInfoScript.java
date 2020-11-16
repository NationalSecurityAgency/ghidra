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
// List function names and entry point addresses to a file in JSON format
//@category Functions

import java.io.File;
import java.io.FileWriter;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class ExportFunctionInfoScript extends GhidraScript {

	private static final String NAME = "name";
	private static final String ENTRY = "entry";

	@Override
	public void run() throws Exception {

		Gson gson = new GsonBuilder().setPrettyPrinting().create();

		File outputFile = askFile("Please Select Output File", "Choose");
		JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile));
		jsonWriter.beginArray();

		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();

			String name = f.getName();
			Address entry = f.getEntryPoint();

			JsonObject json = new JsonObject();
			json.addProperty(NAME, name);
			json.addProperty(ENTRY, entry.toString());

			gson.toJson(json, jsonWriter);
		}

		jsonWriter.endArray();
		jsonWriter.close();

		println("Wrote functions to " + outputFile);
	}
}
