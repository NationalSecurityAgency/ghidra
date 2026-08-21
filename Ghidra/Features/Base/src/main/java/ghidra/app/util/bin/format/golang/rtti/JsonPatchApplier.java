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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.*;

import ghidra.app.util.bin.format.golang.rtti.JsonPatch.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Simplistic implementation, applies a json diff (see https://github.com/josephburnett/jd)
 * to an in memory json element to create a new json value.
 * <p>
 * Does not use any context hints in the diff to correct for mismatches, hence should only be used
 * against the exact original value to produce the new value, useful for compressing json files
 * that are derived from each other. 
 */
public class JsonPatchApplier {

	private static final String ROOT_ELEM_NAME = "rootElement";

	private JsonObject rootContainer = new JsonObject();

	public JsonPatchApplier(JsonElement json) {
		rootContainer.add(ROOT_ELEM_NAME, json);
	}

	public JsonPatchApplier(File baseFile) throws IOException {
		try (FileReader reader = new FileReader(baseFile, StandardCharsets.UTF_8);) {
			rootContainer.add(ROOT_ELEM_NAME, JsonParser.parseReader(reader));
		}
	}

	public JsonElement getJson() {
		return rootContainer.get(ROOT_ELEM_NAME);
	}

	public void apply(String patchString, TaskMonitor monitor)
			throws IOException, CancelledException {
		apply(JsonPatch.read(patchString), monitor);
	}

	public void apply(JsonPatch patch, TaskMonitor monitor) throws IOException, CancelledException {
		for (PatchSection section : patch.getSections()) {
			monitor.increment();
			applySection(section);
		}
	}

	public void writeJson(File destFile) throws IOException {
		try (FileWriter fw = new FileWriter(destFile)) {
			new Gson().toJson(getJson(), fw);
		}
	}

	private void applySection(PatchSection section) throws IOException {
		JsonArray path = section.path();
		List<PatchLine> lines = section.lines();

		JsonElement parent = findParent(path);
		JsonElement targetId =
			path.size() > 0 ? path.get(path.size() - 1) : new JsonPrimitive(ROOT_ELEM_NAME); // special case to handle bare values without container

		if (targetId instanceof JsonPrimitive prim && prim.isString() &&
			parent instanceof JsonObject parentObj) {
			String targetName = prim.getAsString();
			int i = 0;
			if (lines.get(i).operation() == PatchOp.REMOVE) {
				parentObj.remove(targetName);
				i++;
			}
			if (i < lines.size() && lines.get(i).operation() == PatchOp.ADD) {
				parentObj.add(targetName, lines.get(i).value());
			}
		}
		else if (targetId instanceof JsonPrimitive prim && prim.isNumber() &&
			parent instanceof JsonArray parentArray) {
			int targetIndex = prim.getAsInt();
			int i;
			for (i = 0; i < lines.size() && lines.get(i).operation() == PatchOp.REMOVE; i++) {
				parentArray.remove(targetIndex);
			}

			// icky logic because you can't insert in a JsonArray at arbitrary location
			List<JsonElement> arrayElems = new ArrayList<>(parentArray.size());
			parentArray.forEach(arrayElems::add);
			for (; i < lines.size() && lines.get(i).operation() == PatchOp.ADD; i++) {
				arrayElems.add(targetIndex, lines.get(i).value());
				targetIndex++;
			}
			if (arrayElems.size() != parentArray.size()) {
				while (parentArray.size() > 0) {
					parentArray.remove(parentArray.size() - 1);
				}
				arrayElems.forEach(parentArray::add);
			}
		}
		else {
			throw new IOException("unsupported section");
		}
	}

	private JsonElement findParent(JsonArray path) throws IOException {
		// handles the corner case of a bare value that is not inside a json container by
		// optionally returning our artificial rootContainer, or the actual json value
		// The code that is determining the targetId of the value also needs to know about this hack

		if (path.size() == 0) {
			return rootContainer;
		}

		JsonElement current = rootContainer.get(ROOT_ELEM_NAME); // skip the root container since there is a path
		if (current == null) {
			// shouldn't happen
			throw new IOException("missing rootContainer element");
		}
		try {
			for (int i = 0; i < path.size() - 1; i++) {
				JsonElement pathElem = path.get(i);
				JsonElement nextElem = null;
				if (pathElem instanceof JsonPrimitive prim) {
					if (prim.isString()) {
						nextElem = current.getAsJsonObject().get(prim.getAsString());
					}
					else if (prim.isNumber()) {
						int index = prim.getAsNumber().intValue();
						nextElem = current.getAsJsonArray().get(index);
					}
				}
				if (nextElem == null) {
					throw new IOException(
						"Could not find next element in path: " + path + ", " + i);
				}
				current = nextElem;
			}
			return current;
		}
		catch (IllegalStateException e) {
			throw new IOException("invalid json diff data");
		}
	}

}
