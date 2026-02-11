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
import java.util.stream.Collectors;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.pcode.Varnode;

/**
 * A p-code userop defined using Sleigh source
 *
 * @param <T> no type in particular, except to match any executor
 */
public interface SleighPcodeUseropDefinition<T> extends PcodeUseropDefinition<T> {
	/** The name of the output symbol */
	String OUT_SYMBOL_NAME = "__op_output";

	/**
	 * A factory for building {@link SleighPcodeUseropDefinition}s.
	 */
	public static class Factory {
		final SleighLanguage language;

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
		public BuilderStage1 define(String name) {
			return new AbstractSleighPcodeUseropDefinition.Builder(this, name);
		}
	}

	/**
	 * A function body, as it depends on the given arguments
	 */
	public interface BodyFunc {
		/**
		 * Generate the body, given the arguments
		 * 
		 * <p>
		 * In general, to refer to an argument, the source can use the corresponding parameter by
		 * name. Ideally, this is always the case, and the generated source does not depend on the
		 * arguments. Where it's useful to have the varnode, for example, is when the size of the
		 * argument needs to be known. In this case, the argument can be retrieved by index, where 0
		 * is the output varnode, and 1-n is each respective input varnode.
		 * 
		 * @param args the varnode argument list
		 * @return the generated source
		 */
		CharSequence generate(List<Varnode> args);
	}

	/**
	 * Stage two of the builder, where parameters can no longer be added
	 */
	public interface BuilderStage2 {
		/**
		 * Add Sleigh source to the body
		 * 
		 * @param additionalBody the additional source
		 * @return the builder
		 */
		BuilderStage2 body(BodyFunc additionalBody);

		/**
		 * Start a new definition for a different signature
		 * 
		 * @return the builder
		 */
		BuilderStage1 overload();

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
		<T> SleighPcodeUseropDefinition<T> build();
	}

	/**
	 * Stage one of the builder, where any operation is allowed
	 */
	public interface BuilderStage1 extends BuilderStage2 {
		/**
		 * Add parameters with the given names (to the end)
		 * 
		 * @param additionalParams the additional parameter names
		 * @return the builder
		 */
		BuilderStage1 params(Collection<String> additionalParams);

		/**
		 * @see #params(Collection)
		 * @param additionalParams the additional parameter names
		 * @return the builder
		 */
		default BuilderStage1 params(String... additionalParams) {
			return params(Arrays.asList(additionalParams));
		}
	}

	/**
	 * One definition for a userop for a given signature (parameters, including output)
	 * 
	 * @param signature the names of the arguments, index 0 being the output
	 * @param body the body source, possibly a function of the arguments
	 */
	public record SignatureDef(List<String> signature, List<BodyFunc> body) {
		/**
		 * Generate the body's source code for the given arguments
		 * 
		 * @param args the argument varnodes
		 * @return the body
		 */
		public String generateBody(List<Varnode> args) {
			return body.stream().map(b -> b.generate(args)).collect(Collectors.joining());
		}

		/**
		 * Generate the body's source code for the given arguments
		 * 
		 * @param args the argument varnodes
		 * @return the body
		 */
		public String generateBody(Varnode... args) {
			return generateBody(Arrays.asList(args));
		}
	}

	/**
	 * Get the Sleigh source that defines this userop
	 *
	 * <p>
	 * The body may or may not actually depend on the arguments. Ideally, it does not, but sometimes
	 * the body may vary depending on the <em>sizes</em> of the arguments. In cases where it is
	 * known the body is fixed, the args parameter may be null or an empty list. When the arguments
	 * are required, index 0 must be the output varnode. If the userop has no output, index 0 may be
	 * null.
	 *
	 * @param args the argument varnodes
	 * @return the body
	 */
	String getBody(List<Varnode> args);

	/**
	 * Get the Sleigh source that defines this userop
	 * 
	 * @see #getBody(List)
	 * @param args the argument varnodes
	 * @return the body
	 */
	default String getBody(Varnode... args) {
		return getBody(Arrays.asList(args));
	}

	/**
	 * Get the p-code program implementing this userop for the given arguments and library.
	 * 
	 * <p>
	 * This will compile and cache a program for each new combination of arguments seen.
	 * 
	 * @param args the operands, output at index 0, and inputs following
	 * @param library the complete userop library
	 * @return the p-code program to be fed to the same executor as invoked this userop, but in a
	 *         new frame
	 */
	PcodeProgram programFor(List<Varnode> args, PcodeUseropLibrary<?> library);
}
