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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;

public abstract class Expr implements RValInternal {
	protected final StructuredSleigh ctx;
	protected final DataType type;

	protected Expr(StructuredSleigh ctx, DataType type) {
		this.ctx = ctx;

		try (Transaction tx = ctx.dtm.openTransaction("Resolve type")) {
			this.type = ctx.dtm.resolve(type, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
	}

	@Override
	public StructuredSleigh getContext() {
		return ctx;
	}

	@Override
	public DataType getType() {
		return type;
	}
}
