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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import ghidra.util.task.TaskMonitor;

/**
 * A default/unknown C13Section class that we have created for completeness (default switch).
 */
class UnknownC13Section extends AbstractUnimplementedC13Section {
	static UnknownC13Section parse(PdbByteReader reader, boolean ignore, TaskMonitor monitor) {
		return new UnknownC13Section(reader, ignore, monitor);
	}

	protected UnknownC13Section(PdbByteReader reader, boolean ignore, TaskMonitor monitor) {
		super(reader, ignore, monitor);
	}
}
