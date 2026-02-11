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

import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.pcode.Varnode;

/**
 * A Sleigh userop definition with multiple signatures
 * 
 * @param <T> no type in particular, except to match any executor
 */
public class OverloadedSleighPcodeUseropDefinition<T>
		extends AbstractSleighPcodeUseropDefinition<T> {
	protected final Map<Integer, SignatureDef> definitions;

	protected OverloadedSleighPcodeUseropDefinition(SleighLanguage language, String name,
			Map<Integer, SignatureDef> definitions) {
		super(language, name);
		this.definitions = definitions;
	}

	@Override
	public int getInputCount() {
		return -1;
	}

	/**
	 * Get the signature and definition for the given argument count
	 * 
	 * @param argCount the argument (or parameter) count
	 * @return the definition, or null if not defined
	 */
	public SignatureDef getSignatureDef(int argCount) {
		return definitions.get(argCount);
	}

	/**
	 * Get all the signatures and definitions for this userop
	 * 
	 * @return the collection of definitions
	 */
	public Collection<SignatureDef> getAllSignatures() {
		return definitions.values();
	}

	private SignatureDef requireSignatureDef(List<Varnode> args) {
		SignatureDef definition = definitions.get(args.size());
		if (definition == null) {
			throw new SleighLinkException("Incorrect number of arguments to " + getName());
		}
		return definition;
	}

	@Override
	public String getBody(List<Varnode> args) {
		SignatureDef definition = requireSignatureDef(args);
		return definition.generateBody(args);
	}

	@Override
	public PcodeProgram programFor(List<Varnode> args, PcodeUseropLibrary<?> library) {
		return cacheByArgs.computeIfAbsent(args, a -> {
			SignatureDef definition = requireSignatureDef(a);
			return SleighProgramCompiler.compileUserop(language, name, definition.signature(),
				definition.generateBody(a), library, a);
		});
	}

	@Override
	public Class<?> getOutputType() {
		return null;
	}
}
