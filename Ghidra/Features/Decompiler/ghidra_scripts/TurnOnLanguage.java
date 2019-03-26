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
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.lang.BasicCompilerSpec;

public class TurnOnLanguage extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Options decompilerPropertyList = currentProgram.getOptions(BasicCompilerSpec.DECOMPILER_PROPERTY_LIST_NAME);
		decompilerPropertyList.registerOption(
			BasicCompilerSpec.DECOMPILER_OUTPUT_LANGUAGE,
			BasicCompilerSpec.DECOMPILER_OUTPUT_DEF,
			null,
			BasicCompilerSpec.DECOMPILER_OUTPUT_DESC);
	}

}
