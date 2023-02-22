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
//An example script for using Structured Sleigh stand alone
//@author 
//@category Sleigh
//@keybinding
//@menupath
//@toolbar

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.SleighPcodeUseropDefinition;
import ghidra.pcode.struct.StructuredSleigh;
import ghidra.program.model.lang.LanguageID;

public class StandAloneStructuredSleighScript extends GhidraScript {
	private SleighLanguage language;

	/**
	 * This exists mostly so we can access the methods of anonymous nested classes deriving from
	 * this one. The "compiler" will need to be able to access the methods, and that's not
	 * ordinarily allowed since anonymous classes are implicitly "private." Conveniently, it also
	 * allows us to implement a default constructor, so that can be elided where used, too.
	 */
	class LookupStructuredSleigh extends StructuredSleigh {
		protected LookupStructuredSleigh() {
			super(language.getDefaultCompilerSpec());
		}

		@Override
		protected Lookup getMethodLookup() {
			return MethodHandles.lookup();
		}
	}

	@Override
	protected void run() throws Exception {
		/*
		 * If you have a target language in mind, perhaps use it, but DATA provides a minimal
		 * context
		 */
		language = (SleighLanguage) getLanguage(new LanguageID("DATA:BE:64:default"));

		Map<String, SleighPcodeUseropDefinition<Object>> ops = new LookupStructuredSleigh() {
			/**
			 * Add two in-memory vectors of 16 longs and store the result in memory
			 * 
			 * @param d pointer to the destination vector
			 * @param s1 pointer to the first operand vector
			 * @param s2 pointer to the second operand vector
			 */
			@StructuredUserop
			public void vector_add(
					@Param(name = "d", type = "int *") Var d,
					@Param(name = "s1", type = "int *") Var s1,
					@Param(name = "s2", type = "int *") Var s2) {
				// Use Java's "for" to generate an unrolled loop
				// We could choose a Sleigh loop, instead. Consider both emu and analysis tradeoffs
				for (int i = 0; i < 16; i++) {
					// This will generate +0 on the first elements, but whatever
					d.index(i).deref().set(s1.index(i).deref().addi(s2.index(i).deref()));
				}
			}

			@StructuredUserop
			public void memcpy(
					@Param(name = "d", type = "void *") Var d,
					@Param(name = "s", type = "void *") Var s,
					@Param(name = "n", type = "long") Var n) { // size_t is not built-in
				Var i = local("i", type("long"));
				// Note that these 2 casts don't generate Sleigh statements
				Var db = d.cast(type("byte *"));
				Var sb = s.cast(type("byte *"));
				// Must use a Sleigh loop here
				_for(i.set(0), i.ltiu(n), i.inc(), () -> {
					db.index(i).deref().set(sb.index(i).deref());
				});
			}
		}.generate();

		/*
		 * Now, dump the generated Sleigh source
		 */
		for (SleighPcodeUseropDefinition<?> userop : ops.values()) {
			print(userop.getName() + "(");
			print(userop.getInputs().stream().collect(Collectors.joining(",")));
			print(") {\n");
			print(userop.getBody());
			print("}\n\n");
		}
	}
}
