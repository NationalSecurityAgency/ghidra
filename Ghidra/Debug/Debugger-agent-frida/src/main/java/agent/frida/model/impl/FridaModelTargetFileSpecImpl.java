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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;

import agent.frida.frida.FridaClient;
import agent.frida.manager.FridaFileSpec;
import agent.frida.model.iface2.FridaModelTargetFileSpec;
import agent.frida.model.iface2.FridaModelTargetMemoryRegion;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "FileSpec",
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class FridaModelTargetFileSpecImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetFileSpec {

	protected static String keyFileSpec(FridaFileSpec file) {
		return PathUtils.makeKey(FridaClient.getId(file));
	}

	private FridaFileSpec fileSpec;

	public FridaModelTargetFileSpecImpl(FridaModelTargetMemoryRegion region, FridaFileSpec fileSpec) {
		super(region.getModel(), region, "File", "FileSpec");
		this.fileSpec = fileSpec;

		if (fileSpec != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				DISPLAY_ATTRIBUTE_NAME, getDescription(), //
				"Path", fileSpec.getPath(), //
				"Offset", fileSpec.getOffset(), //
				"Size", fileSpec.getSize() //
			), "Initialized");
		}
	}

	public String getDescription() {
		return fileSpec.getFilename();
	}

}
