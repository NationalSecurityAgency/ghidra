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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.*;
import java.util.*;

import com.google.gson.*;

import utilities.util.FileUtilities;

/**
 * Represents a sequence of operations that describe how a json file has changed.
 * <p>
 * This implementation currently only supports reading jd (https://github.com/josephburnett/jd)
 * native format diffs.
 */
public class JsonPatch {
	/**
	 * Creates a new instance using the contents in the supplied string.
	 * 
	 * @param patchString diff text
	 * @return new JsonPatch instance
	 * @throws IOException if error
	 */
	public static JsonPatch read(String patchString) throws IOException {
		return read(FileUtilities.getLines(new BufferedReader(new StringReader(patchString)))
				.listIterator());
	}

	/**
	 * Creates a new instance using the contents of the supplied file.
	 * 
	 * @param patchFile path to file containing json diff
	 * @return new JsonPatch instance
	 * @throws IOException if error
	 */
	public static JsonPatch read(File patchFile) throws IOException {
		List<String> lines = FileUtilities.getLines(patchFile);
		return read(lines.listIterator());
	}

	/**
	 * Creates a new instance using the contents of the supplied text lines.
	 * 
	 * @param lineIterator iterator that provides lines of text containing the json diff
	 * @return new JsonPatch instance
	 * @throws IOException if error
	 */
	public static JsonPatch read(ListIterator<String> lineIterator) throws IOException {
		List<PatchSection> sections = new ArrayList<>();
		PatchSection section;
		while (lineIterator.hasNext() && (section = readPatchSection(lineIterator)) != null) {
			sections.add(section);
		}
		return new JsonPatch(sections);
	}

	/**
	 * Creates a new instance using the contents of the jsonarray.  Allows storing a json
	 * patch in a json document.
	 * 
	 * @param patchSectionElements json array containing the json diff sections
	 * @return new JsonPatch instance
	 * @throws IOException if error
	 */
	public static JsonPatch read(JsonArray patchSectionElements) throws IOException {
		List<PatchSection> sections = new ArrayList<>();
		for (int i = 0; i < patchSectionElements.size(); i++) {
			sections.add(readPatchSection(patchSectionElements.get(i).getAsJsonObject()));
		}
		return new JsonPatch(sections);
	}

	private List<PatchSection> sections;

	public JsonPatch(List<PatchSection> sections) {
		this.sections = sections;
	}

	public int getSectionCount() {
		return sections.size();
	}

	public List<PatchSection> getSections() {
		return sections;
	}

	/**
	 * Converts this patch to a json array.
	 * 
	 * @return json array with json encoded patch/diff elements.
	 */
	public JsonArray toJson() {
		JsonArray result = new JsonArray();
		sections.forEach(section -> result.add(section.toJson()));
		return result;
	}

	//----------------------------------------------------------------------------------------------

	public enum PatchOp {
		ADD, REMOVE, CONTEXT;

		public static PatchOp fromChar(char ch) {
			return switch (ch) {
				case '+' -> PatchOp.ADD;
				case '-' -> PatchOp.REMOVE;
				default -> null;
			};
		}

		public String getOpChar() {
			return switch (this) {
				case ADD -> "+";
				case REMOVE -> "-";
				default -> "??";
			};
		}
	}

	public record PatchSection(JsonArray path, List<PatchLine> lines) {
		public JsonObject toJson() {
			// { "path": [blah, blha], "elements": [ { "op": "+/-", "value": jsonvalue }, * ] }
			JsonObject result = new JsonObject();
			result.add("path", path);
			JsonArray elements = new JsonArray();
			lines.forEach(line -> elements.add(line.toJson()));
			result.add("elements", elements);
			return result;
		}
	}

	public record PatchLine(PatchOp operation, JsonElement value) {
		public JsonObject toJson() {
			// { "op": "+/-", "value": jsonvalue }
			JsonObject result = new JsonObject();
			result.addProperty("op", operation.getOpChar());
			if (value != null) {
				result.add("value", value);
			}
			return result;
		}
	}

	private static PatchSection readPatchSection(JsonObject patchSectionElem) throws IOException {
		JsonArray path = patchSectionElem.get("path") instanceof JsonArray arr ? arr : null;
		JsonArray elements = patchSectionElem.get("elements") instanceof JsonArray arr ? arr : null;
		if (path == null || elements == null) {
			throw new IOException();
		}
		List<PatchLine> lines = new ArrayList<>();
		for (int i = 0; i < elements.size(); i++) {
			lines.add(lineFromJson(elements.get(i).getAsJsonObject()));
		}
		return new PatchSection(path, lines);
	}

	private static PatchLine lineFromJson(JsonObject jsonObj) throws IOException {
		PatchOp op = jsonObj.get("op") instanceof JsonPrimitive prim
				? PatchOp.fromChar(prim.getAsCharacter())
				: null;
		JsonElement value = jsonObj.get("value");
		if (op == null || op == PatchOp.ADD && value == null) {
			throw new IOException("bad patch element: " + jsonObj);
		}
		return new PatchLine(op, value);
	}

	private static PatchSection readPatchSection(ListIterator<String> lineIt) throws IOException {
		String line = lineIt.hasNext() ? lineIt.next() : null;
		if (line == null) {
			return null;
		}
		if (!line.startsWith("@ ")) {
			throw new IOException("bad start of patch section: " + line);
		}

		JsonElement pathElem = JsonParser.parseString(line.substring(2));

		List<PatchLine> patchLines = new ArrayList<>();
		while (lineIt.hasNext()) {
			line = lineIt.next();
			if (line.length() < 3) {
				// probably a context line, just skip it
				continue;
			}
			char opChar = line.charAt(0);
			if (opChar == '+' || opChar == '-') {
				PatchOp patchOp = PatchOp.fromChar(opChar);
				JsonElement val =
					patchOp == PatchOp.ADD ? JsonParser.parseString(line.substring(2)) : null;
				patchLines.add(new PatchLine(patchOp, val));
			}
			else if (opChar == '@') {
				lineIt.previous();
				break;
			}
		}
		PatchSection section = new PatchSection(pathElem.getAsJsonArray(), patchLines);
		return section;
	}

}
