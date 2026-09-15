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
package ghidra.app.plugin.core.debug.taint;

import ghidra.app.plugin.core.debug.taint.EmulatorTaintState.KTV;
import ghidra.program.model.data.ISF.AbstractIsfWriter.Exclude;
import ghidra.program.model.data.ISF.IsfObject;

public class ExtKeyValue implements IsfObject {

	String name;
	String displayName;
	String type;
	String value;
	String taintLabels;

	@Exclude
	private int index;

	public ExtKeyValue(KTV ktv) {
		this.name = ktv.key();
		this.displayName = ktv.displayName();
		this.type = "Instruction";
		this.value = ktv.value();
		this.taintLabels = "[" + ktv.value() + "]";
	}

}
