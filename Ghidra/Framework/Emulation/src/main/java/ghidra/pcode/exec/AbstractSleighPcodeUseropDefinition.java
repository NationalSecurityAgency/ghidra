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

import java.lang.reflect.Method;
import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A abstract Sleigh userop definition
 * 
 * @param <T> no type in particular, except to match any executor
 */
public abstract class AbstractSleighPcodeUseropDefinition<T>
		implements SleighPcodeUseropDefinition<T> {

	/**
	 * A builder for a particular userop
	 * 
	 * @see SleighPcodeUseropDefinition.Factory
	 */
	public static class Builder implements BuilderStage1 {
		private final Factory factory;
		private final String name;
		private final Map<Integer, SignatureDef> definitions = new HashMap<>();
		private final List<String> params = new ArrayList<>();
		private final List<BodyFunc> body = new ArrayList<>();

		protected Builder(Factory factory, String name) {
			this.factory = factory;
			this.name = name;

			params(OUT_SYMBOL_NAME);
		}

		@Override
		public Builder params(Collection<String> additionalParams) {
			this.params.addAll(additionalParams);
			return this;
		}

		@Override
		public Builder body(BodyFunc additionalBody) {
			body.add(additionalBody);
			return this;
		}

		@Override
		public BuilderStage1 overload() {
			SignatureDef exists = definitions.put(params.size(),
				new SignatureDef(List.copyOf(params), List.copyOf(body)));

			params.clear();
			body.clear();
			params(OUT_SYMBOL_NAME);

			if (exists != null) {
				throw new IllegalArgumentException("Definition for this signature already exists");
			}
			return this;
		}

		/**
		 * Build the actual definition
		 * 
		 * <p>
		 * NOTE: Compilation of the sleigh source is delayed until the first invocation, since the
		 * compiler must know about the varnodes used as parameters. TODO: There may be some way to
		 * template it at the p-code level instead of the Sleigh source level.
		 * 
		 * @param <T> no particular type, except to match the executor
		 * @return the definition
		 */
		@Override
		public <T> SleighPcodeUseropDefinition<T> build() {
			overload();
			if (definitions.size() == 1) {
				return new FixedSleighPcodeUseropDefinition<T>(factory.language, name,
					definitions.values().iterator().next());
			}
			return new OverloadedSleighPcodeUseropDefinition<>(factory.language, name,
				Map.copyOf(definitions));
		}
	}

	protected final SleighLanguage language;
	protected final String name;

	protected final Map<List<Varnode>, PcodeProgram> cacheByArgs = new HashMap<>();

	protected AbstractSleighPcodeUseropDefinition(SleighLanguage language, String name) {
		this.language = language;
		this.name = name;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public boolean isFunctional() {
		return false;
	}

	@Override
	public boolean hasSideEffects() {
		return true;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote We could scan the p-code ops for any that write to the contextreg; however, at the
	 *           moment, that is highly unconventional and perhaps even considered an error. If that
	 *           becomes more common, or even recommended, then we can detect it and behave
	 *           accordingly during interpretation (whether for execution or translation).
	 */
	@Override
	public boolean modifiesContext() {
		return false;
	}

	@Override
	public boolean canInlinePcode() {
		return true;
	}

	@Override
	public Method getJavaMethod() {
		return null;
	}

	@Override
	public PcodeUseropLibrary<T> getDefiningLibrary() {
		return null;
	}

	@Override
	public void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library, PcodeOp op,
			Varnode outArg, List<Varnode> inArgs) {
		List<Varnode> args = new ArrayList<>(inArgs.size() + 1);
		args.add(outArg);
		args.addAll(inArgs);
		PcodeProgram program = programFor(args, library);
		executor.execute(program, library);
	}
}
