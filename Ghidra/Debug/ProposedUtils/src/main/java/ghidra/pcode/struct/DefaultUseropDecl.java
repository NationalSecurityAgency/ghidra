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

import java.util.List;

import ghidra.pcode.struct.StructuredSleigh.*;
import ghidra.program.model.data.DataType;

public class DefaultUseropDecl implements UseropDecl {
	private final StructuredSleigh ctx;
	private final DataType retType;
	private final String name;
	private final List<DataType> paramTypes;

	public DefaultUseropDecl(StructuredSleigh ctx, DataType retType, String name,
			List<DataType> paramTypes) {
		this.ctx = ctx;
		this.retType = retType;
		this.name = name;
		this.paramTypes = List.copyOf(paramTypes);
	}

	@Override
	public DataType getReturnType() {
		return retType;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public List<DataType> getParameterTypes() {
		return paramTypes;
	}

	@Override
	public StmtWithVal call(RVal... args) {
		if (paramTypes.size() != args.length) {
			ctx.emitParameterCountMismatch(this, List.of(args));
		}
		for (int i = 0; i < args.length && i < paramTypes.size(); i++) {
			DataType pType = paramTypes.get(i);
			RVal a = args[i];
			if (!ctx.isAssignable(pType, a.getType())) {
				ctx.emitParameterTypeMismatch(this, i, a);
			}
		}
		if (retType.getLength() == 0) {
			return new VoidExprStmt(ctx, new CallExpr(ctx, this, List.of(args)));
		}
		return new AssignStmt(ctx, ctx.temp(retType), new CallExpr(ctx, this, List.of(args)));
	}
}
