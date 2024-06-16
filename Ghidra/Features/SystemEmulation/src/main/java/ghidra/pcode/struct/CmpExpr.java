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

import ghidra.pcode.struct.StructuredSleigh.RVal;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;

class CmpExpr extends BinExpr {
	enum Op {
		EQ("==") {
			@Override
			Op not() {
				return NEQ;
			}
		},
		NEQ("!=") {
			@Override
			Op not() {
				return EQ;
			}
		},
		EQF("f==") {
			@Override
			Op not() {
				return NEQF;
			}
		},
		NEQF("f!=") {
			@Override
			Op not() {
				return EQF;
			}
		},
		LTIU("<") {
			@Override
			Op not() {
				return GTEIU;
			}
		},
		LTIS("s<") {
			@Override
			Op not() {
				return GTEIS;
			}
		},
		LTF("f<") {
			@Override
			Op not() {
				return GTEF;
			}
		},
		LTEIU("<=") {
			@Override
			Op not() {
				return GTIU;
			}
		},
		LTEIS("s<=") {
			@Override
			Op not() {
				return GTIS;
			}
		},
		LTEF("f<=") {
			@Override
			Op not() {
				return GTF;
			}
		},
		GTIU(">") {
			@Override
			Op not() {
				return LTEIU;
			}
		},
		GTIS("s>") {
			@Override
			Op not() {
				return LTEIS;
			}
		},
		GTF("f>") {
			@Override
			Op not() {
				return LTEF;
			}
		},
		GTEIU(">=") {
			@Override
			Op not() {
				return LTIU;
			}
		},
		GTEIS("s>=") {
			@Override
			Op not() {
				return LTIS;
			}
		},
		GTEF("f>=") {
			@Override
			Op not() {
				return LTF;
			}
		},
		;

		private final String str;

		Op(String str) {
			this.str = str;
		}

		abstract Op not();
	}

	protected Op op;

	private CmpExpr(StructuredSleigh ctx, RVal lhs, Op op, RVal rhs, DataType type) {
		super(ctx, lhs, op.str, rhs, type);
		this.op = op;
	}

	protected CmpExpr(StructuredSleigh ctx, RVal lhs, Op op, RVal rhs) {
		this(ctx, lhs, op, rhs, BooleanDataType.dataType);
	}

	@Override
	public RVal notb() {
		return new CmpExpr(ctx, lhs, op.not(), rhs, type);
	}
}
