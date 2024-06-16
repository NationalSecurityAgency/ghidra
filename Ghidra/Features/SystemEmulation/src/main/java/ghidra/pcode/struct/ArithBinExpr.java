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

class ArithBinExpr extends BinExpr {
	enum Op {
		ORB("||"),
		ORI("|"),
		XORB("^^"),
		XORI("^"),
		ANDB("&&"),
		ANDI("&"),
		SHLI("<<"),
		SHRIU(">>"),
		SHRIS("s>>"),
		ADDI("+"),
		ADDF("f+"),
		SUBI("-"),
		SUBF("f-"),
		MULI("*"),
		MULF("f*"),
		DIVIU("/"),
		DIVIS("s/"),
		DIVF("f/"),
		REMIU("%"),
		REMIS("s%"),
		;

		private final String str;

		Op(String str) {
			this.str = str;
		}
	}

	protected ArithBinExpr(StructuredSleigh ctx, RVal lhs, Op op, RVal rhs) {
		// TODO: Should take more general of two types?
		super(ctx, lhs, op.str, rhs, lhs.getType());
	}
}
