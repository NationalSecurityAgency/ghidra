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

import ghidra.pcode.struct.StructuredSleigh.*;

interface LValInternal extends LVal, RValInternal {
	@Override
	default LVal field(String name) {
		return new FieldExpr(getContext(), this, name);
	}

	@Override
	default LVal index(RVal index) {
		return new IndexExpr(getContext(), this, index);
	}

	@Override
	default LVal index(long index) {
		// TODO: Since constant, fold with type size
		return index(getContext().lit(index, 8));
	}

	@Override
	default AssignStmt set(RVal rhs) {
		StructuredSleigh ctx = getContext();
		if (!ctx.isAssignable(getType(), rhs.getType())) {
			ctx.emitAssignmentTypeMismatch(this, rhs);
		}
		return new AssignStmt(ctx, this, rhs);
	}

	@Override
	default AssignStmt set(long rhs) {
		return set(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default StmtWithVal addiTo(RVal rhs) {
		return set(addi(rhs));
	}

	@Override
	default StmtWithVal addiTo(long rhs) {
		return set(addi(rhs));
	}

	@Override
	default StmtWithVal inc() {
		return addiTo(1);
	}
}
