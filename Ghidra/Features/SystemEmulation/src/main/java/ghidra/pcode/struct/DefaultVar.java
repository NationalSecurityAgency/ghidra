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
package ghidra.pcode.struct;

import db.Transaction;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.pcode.struct.StructuredSleigh.Var;
import ghidra.pcodeCPort.slghsymbol.SleighSymbol;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.lang.PcodeParser;

class DefaultVar implements LValInternal, Var {
	/**
	 * The rule for name collision
	 */
	enum Check {
		/** The name may or may not already be defined by the language */
		NONE {
			@Override
			void check(PcodeParser parser, String name) {
				// Do nothing
			}
		},
		/** The name must already be defined by the language so it can be imported */
		IMPORT {
			@Override
			void check(PcodeParser parser, String name) {
				// TODO: Also check the type is compatible?
				SleighSymbol symbol = parser.findSymbol(name);
				if (symbol == null) {
					throw new SleighException("Missing symbol '" + name + "'");
				}
			}
		},
		/** The name cannot already be defined by the language so it is free */
		FREE {
			@Override
			void check(PcodeParser parser, String name) {
				SleighSymbol symbol = parser.findSymbol(name);
				if (symbol != null) {
					throw new SleighException(
						"Duplicate symbol '" + name + "': Already defined by the language");
				}
			}
		};

		/**
		 * Check that the given name obeys the rule
		 * 
		 * @param parser a parser bound to the target language
		 * @param name the name to check
		 */
		abstract void check(PcodeParser parser, String name);
	}

	protected final StructuredSleigh ctx;
	protected final String name;
	protected final DataType type;

	/**
	 * Create a new variable
	 * 
	 * @param ctx the context
	 * @param check the rule to check the name
	 * @param name the name of the variable
	 * @param type the type of the variable
	 */
	protected DefaultVar(StructuredSleigh ctx, Check check, String name, DataType type) {
		check.check(ctx.parser, name);
		this.ctx = ctx;
		this.name = name;
		try (Transaction tx = ctx.dtm.openTransaction("Resolve type")) {
			this.type = ctx.dtm.resolve(type, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
	}

	@Override
	public Var cast(DataType type) {
		return new DefaultVar(ctx, Check.NONE, name, type);
	}

	@Override
	public String toString() {
		return "<" + getClass().getSimpleName() + ": " + name + " : " + type + ">";
	}

	@Override
	public StructuredSleigh getContext() {
		return ctx;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public DataType getType() {
		return type;
	}

	@Override
	public StringTree generate(RValInternal parent) {
		return StringTree.single(name);
	}
}
