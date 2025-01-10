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
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.pcode.Varnode;

/**
 * A p-code userop defined using Sleigh source
 *
 * @param <T> no type in particular, except to match any executor
 */
public class SleighPcodeUseropDefinition<T> implements PcodeUseropDefinition<T> {
	public static final String OUT_SYMBOL_NAME = "__op_output";

	/**
	 * A factory for building {@link SleighPcodeUseropDefinition}s.
	 */
	public static class Factory {
		private final SleighLanguage language;

		/**
		 * Construct a factory for the given language
		 * 
		 * @param language the language
		 */
		public Factory(SleighLanguage language) {
			this.language = language;
		}

		/**
		 * Begin building the definition for a userop with the given name
		 * 
		 * @param name the name of the new userop
		 * @return a builder for the userop
		 */
		public Builder define(String name) {
			return new Builder(this, name);
		}
	}

	/**
	 * A builder for a particular userop
	 * 
	 * @see Factory
	 */
	public static class Builder {
		private final Factory factory;
		private final String name;
		private final List<String> params = new ArrayList<>();
		private final StringBuffer body = new StringBuffer();

		protected Builder(Factory factory, String name) {
			this.factory = factory;
			this.name = name;

			params(OUT_SYMBOL_NAME);
		}

		/**
		 * Add parameters with the given names (to the end)
		 * 
		 * @param additionalParams the additional parameter names
		 * @return this builder
		 */
		public Builder params(Collection<String> additionalParams) {
			this.params.addAll(additionalParams);
			return this;
		}

		/**
		 * @see #params(Collection)
		 * @param additionalParams the additional parameter names
		 * @return this builder
		 */
		public Builder params(String... additionalParams) {
			return this.params(Arrays.asList(additionalParams));
		}

		/**
		 * Add Sleigh source to the body
		 * 
		 * @param additionalBody the additional source
		 * @return this builder
		 */
		public Builder body(CharSequence additionalBody) {
			body.append(additionalBody);
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
		public <T> SleighPcodeUseropDefinition<T> build() {
			return new SleighPcodeUseropDefinition<>(factory.language, name, List.copyOf(params),
				body.toString());
		}
	}

	private final SleighLanguage language;
	private final String name;
	private final List<String> params;
	private final String body;

	private final Map<List<Varnode>, PcodeProgram> cacheByArgs = new HashMap<>();

	protected SleighPcodeUseropDefinition(SleighLanguage language, String name, List<String> params,
			String body) {
		this.language = language;
		this.name = name;
		this.params = params;
		this.body = body;
	}

	/**
	 * Get the p-code program implementing this userop for the given arguments and library.
	 * 
	 * <p>
	 * This will compile and cache a program for each new combination of arguments seen.
	 * 
	 * @param outArg the output operand, if applicable
	 * @param inArgs the input operands
	 * @param library the complete userop library
	 * @return the p-code program to be fed to the same executor as invoked this userop, but in a
	 *         new frame
	 */
	public PcodeProgram programFor(Varnode outArg, List<Varnode> inArgs,
			PcodeUseropLibrary<?> library) {
		List<Varnode> args = new ArrayList<>(inArgs.size() + 1);
		args.add(outArg);
		args.addAll(inArgs);
		return cacheByArgs.computeIfAbsent(args,
			a -> SleighProgramCompiler.compileUserop(language, name, params, body, library, a));
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getInputCount() {
		return params.size() - 1; // account for __op_output
	}

	@Override
	public void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library,
			Varnode outArg, List<Varnode> inArgs) {
		PcodeProgram program = programFor(outArg, inArgs, library);
		executor.execute(program, library);
	}

	/**
	 * Get the names of the inputs in order
	 * 
	 * @return the input names
	 */
	public List<String> getInputs() {
		return params;
	}

	/**
	 * Get the Sleigh source that defines this userop
	 * 
	 * @return the lines
	 */
	public String getBody() {
		return body;
	}

	@Override
	public boolean isFunctional() {
		return false;
	}

	@Override
	public boolean hasSideEffects() {
		return true;
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
}
