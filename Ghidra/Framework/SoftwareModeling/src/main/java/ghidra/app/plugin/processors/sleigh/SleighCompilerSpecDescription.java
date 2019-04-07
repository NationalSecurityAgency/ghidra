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
package ghidra.app.plugin.processors.sleigh;

import generic.jar.ResourceFile;
import ghidra.program.model.lang.BasicCompilerSpecDescription;
import ghidra.program.model.lang.CompilerSpecID;

public class SleighCompilerSpecDescription extends BasicCompilerSpecDescription {
	private final ResourceFile file;

	public SleighCompilerSpecDescription(CompilerSpecID id, String name, ResourceFile file) {
		super(id, name);
		this.file = file;
	}

	public ResourceFile getFile() {
		return file;
	}

	@Override
	public String getSource() {
		return this.file.toString();
	}
}
