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
 */
public interface SleighPcodeUseropDefinition extends PcodeUseropDefinition<Object> {
	/** The factory for defining userops with Sleigh */
	Factory FACTORY = Factory.INSTANCE;
	/** The name of the output symbol */
	String OUT_SYMBOL_NAME = "__op_output";
	/** The varnode list containing only one null */
	List<Varnode> EMPTY_ARGS = Collections.unmodifiableList(Arrays.asList(new Varnode[] { null }));

	/**
	 * A factory for building {@link SleighPcodeUseropDefinition}s.
	 */
	public enum Factory {
		/** The factory */
		INSTANCE;

		/**
		 * Begin building the definition for a userop with the given name
		 * 
		 * @param name the name of the new userop
		 * @return a builder for the userop
		 */
		public BuilderStage1 define(String name) {
			return new AbstractSleighPcodeUseropDefinition.Builder(name);
		}
	}

	/**
	 * A function body, as it depends on the given arguments
	 */
	public interface BodyFunc {
		/**
		 * Generate the body, given the arguments
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
		 * <p>
		 * NOTE: Compilation of the sleigh source is delayed until the first invocation, since the
		 * compiler must know about the varnodes used as parameters. TODO: There may be some way to
		 * template it at the p-code level instead of the Sleigh source level.
		 * 
		 * @return the definition
		 */
		SleighPcodeUseropDefinition build();
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
	 * <p>
	 * This will compile and cache a program for each new combination of arguments seen.
	 * 
	 * @param language the language of the executor
	 * @param args the operands, output at index 0, and inputs following
	 * @param library the complete userop library
	 * @return the p-code program to be fed to the same executor as invoked this userop, but in a
	 *         new frame
	 */
	PcodeProgram programFor(SleighLanguage language, List<Varnode> args,
			PcodeUseropLibrary<?> library);

	/**
	 * Cast this Sleigh p-code userop definition to one of the required type
	 * 
	 * @param <T> the executor's, library's, etc. type
	 * @return this same definition
	 */
	@SuppressWarnings("unchecked")
	default <T> PcodeUseropDefinition<T> cast() {
		return (PcodeUseropDefinition<T>) this;
	}

	/**
	 * Cast a userop definition to a Sleigh-defined one
	 * <p>
	 * For some reason, the usual syntax in Java is forbidden, probably because it's of {@code <T>}
	 * and not {@code <?>}....
	 * 
	 * @param def the userop definition
	 * @return the userop definition, if it is a Sleigh-defined one
	 * @throws ClassCastException if def is not a Sleigh-defined userop
	 */
	static SleighPcodeUseropDefinition cast(PcodeUseropDefinition<?> def) {
		return (SleighPcodeUseropDefinition) def;
	}
}
