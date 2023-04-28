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
package ghidra.program.model.data.ISF;

import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonArray;

public class IsfLinuxOS implements IsfObject {

	public JsonArray symbols = new JsonArray();
	public JsonArray types = new JsonArray();

	public IsfLinuxOS(Gson gson, Map<String, String> metaData) {
		IsfLinuxProgram pgm = new IsfLinuxProgram(metaData);
		symbols.add(gson.toJsonTree(pgm));
		types.add(gson.toJsonTree(pgm));
	}

}
