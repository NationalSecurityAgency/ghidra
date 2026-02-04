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
package ghidra.pcode.exec;

import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.pcode.Varnode;

/**
 * A Sleigh userop definition with one signature
 * 
 * @param <T> no type in particular, except to match any executor
 */
public class FixedSleighPcodeUseropDefinition<T> extends AbstractSleighPcodeUseropDefinition<T> {
	protected final SignatureDef definition;

	protected FixedSleighPcodeUseropDefinition(SleighLanguage language, String name,
			SignatureDef definition) {
		super(language, name);
		this.definition = definition;
	}

	@Override
	public int getInputCount() {
		return definition.signature().size() - 1; // account for __op_output 
	}

	/**
	 * Get the single signature and definition
	 * 
	 * @return the definition
	 */
	public SignatureDef getSignatureDef() {
		return definition;
	}

	@Override
	public String getBody(List<Varnode> args) {
		return definition.generateBody(args);
	}

	@Override
	public PcodeProgram programFor(List<Varnode> args, PcodeUseropLibrary<?> library) {
		return cacheByArgs.computeIfAbsent(args,
			a -> SleighProgramCompiler.compileUserop(language, name, definition.signature(),
				definition.generateBody(a), library, a));
	}

	@Override
	public Class<?> getOutputType() {
		return null;
	}
}
