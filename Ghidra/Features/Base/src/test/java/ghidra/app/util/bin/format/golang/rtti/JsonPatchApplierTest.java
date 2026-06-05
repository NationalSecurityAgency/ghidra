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

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class JsonPatchApplierTest {

	@Test
	public void test() throws IOException, CancelledException {
		JsonElement json = JsonParser
				.parseString("{\"a\":\"a value\",\"b\":[0,1,1,2,3],\"c\":[55,66,77],\"z\":{}}");
		JsonElement expectedJson = JsonParser.parseString(
			"{\"a\":\"a value\",\"b\":[0,1.5,2,2,2,2,2.5,3,55,66],\"c\":[55,99,99],\"d\":{\"cc\":\"cee\"}}");
		String patchString = """
				@ ["b",1]
				  0
				- 1
				- 1
				+ 1.5
				  2
				@ ["b",3]
				  2
				+ 2
				+ 2
				+ 2
				+ 2.5
				  3
				@ ["b",8]
				  3
				+ 55
				+ 66
				]
				@ ["c",1]
				  55
				- 66
				- 77
				+ 99
				+ 99
				]
				@ ["z"]
				- {}
				@ ["d"]
				+ {"cc":"cee"}""";
		JsonPatchApplier jpa = new JsonPatchApplier(json);
		jpa.apply(patchString, TaskMonitor.DUMMY);

		assertEquals(expectedJson, jpa.getJson());
	}

	@Test
	public void testEmptyPatch() throws IOException, CancelledException {
		JsonElement json = JsonParser.parseString("{\"a\":\"a value\"}");
		JsonElement expectedJson = JsonParser.parseString("{\"a\":\"a value\"}");
		String patchString = "";
		JsonPatchApplier jpa = new JsonPatchApplier(json);
		jpa.apply(patchString, TaskMonitor.DUMMY);

		assertEquals(expectedJson, jpa.getJson());
	}

	@Test
	public void testEndOfArrayAdditions() throws IOException, CancelledException {
		JsonElement json = JsonParser.parseString("[5,6,7.5]");
		JsonElement expectedJson = JsonParser.parseString("[5,5.5,6,7.5,\"string\"]");
		String patchString = """
				@ [1]
				  5
				+ 5.5
				  6
				@ [4]
				  7.5
				+ "string"
				]""";
		JsonPatchApplier jpa = new JsonPatchApplier(json);
		jpa.apply(patchString, TaskMonitor.DUMMY);

		assertEquals(expectedJson, jpa.getJson());
	}

	@Test
	public void testBareValue() throws IOException, CancelledException {
		JsonElement json = JsonParser.parseString("5.5");
		JsonElement expectedJson = JsonParser.parseString("\"string value\"");
		String patchString = """
				@ []
				- 5.5
				+ "string value"
				""";
		JsonPatchApplier jpa = new JsonPatchApplier(json);
		jpa.apply(patchString, TaskMonitor.DUMMY);

		assertEquals(expectedJson, jpa.getJson());
	}

	@Test
	public void testBareValueDelete() throws IOException, CancelledException {
		JsonElement json = JsonParser.parseString("5.5");
		JsonElement expectedJson = null;
		String patchString = """
				@ []
				- 5.5
				""";
		JsonPatchApplier jpa = new JsonPatchApplier(json);
		jpa.apply(patchString, TaskMonitor.DUMMY);

		assertEquals(expectedJson, jpa.getJson());
	}

	@Test
	public void testArrayMods() throws IOException, CancelledException {
		JsonElement json = JsonParser.parseString(
			"{\"a\":\"a value\",\"b\":[0,1,1,2,3],\"c\":[55,66,77],\"z\":{},\"name\":{\"subname\":{\"blah\":\"1\"}}}");
		JsonElement expectedJson = JsonParser.parseString(
			"{\"a\":\"a value\",\"b\":[0,1.5,2,2,2,2,2.5,3,55,66],\"c\":[55,99,99],\"d\":{\"cc\":\"cee\"},\"name\":{\"subname\":{\"blah\":\"2\",\"test\":44}}}");
		String patchString = """
				@ ["b",1]
				  0
				- 1
				- 1
				+ 1.5
				  2
				@ ["b",3]
				  2
				+ 2
				+ 2
				+ 2
				+ 2.5
				  3
				@ ["b",8]
				  3
				+ 55
				+ 66
				]
				@ ["c",1]
				  55
				- 66
				- 77
				+ 99
				+ 99
				]
				@ ["name","subname","blah"]
				- "1"
				+ "2"
				@ ["name","subname","test"]
				+ 44
				@ ["z"]
				- {}
				@ ["d"]
				+ {"cc":"cee"}""";
		JsonPatchApplier jpa = new JsonPatchApplier(json);
		jpa.apply(patchString, TaskMonitor.DUMMY);

		assertEquals(expectedJson, jpa.getJson());
	}

}
