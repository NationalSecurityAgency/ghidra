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
package ghidra.dbg.sctl.client;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncLazyValue;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.attributes.TargetNamedDataTypeRef;
import ghidra.dbg.sctl.protocol.types.*;
import ghidra.dbg.target.TargetNamedDataType;
import ghidra.dbg.util.PathUtils;

public abstract class SctlTargetNamedDataType<T extends SctlTargetNamedDataType<T, M>, M extends SctlTargetDataTypeMember>
		extends DefaultTargetObject<M, SctlTargetDataTypeNamespace>
		implements TargetNamedDataType<T> {

	protected static String indexStruct(SctlStructTypeName tStruct) {
		return "struct " + tStruct.tag.str;
	}

	protected static String indexUnion(SctlUnionTypeName tUnion) {
		return "union " + tUnion.tag.str;
	}

	protected static String indexEnum(SctlEnumTypeName tEnum) {
		return "enum " + tEnum.tag.str;
	}

	protected static String indexTypedef(SctlTypedefTypeName tTypedef) {
		return "typedef " + tTypedef.tid.str;
	}

	protected static String indexFunction(SctlFunctionTypeName tFunction) {
		// SCTL does not name these. It'd be nice to have something more stable
		return "function " + "sig" + System.identityHashCode(tFunction);
	}

	protected static String indexType(AbstractSctlTypeName tname) {
		if (tname instanceof SctlStructTypeName) {
			return indexStruct((SctlStructTypeName) tname);
		}
		if (tname instanceof SctlUnionTypeName) {
			return indexUnion((SctlUnionTypeName) tname);
		}
		if (tname instanceof SctlEnumTypeName) {
			return indexEnum((SctlEnumTypeName) tname);
		}
		if (tname instanceof SctlTypedefTypeName) {
			return indexTypedef((SctlTypedefTypeName) tname);
		}
		if (tname instanceof SctlFunctionTypeName) {
			return indexFunction((SctlFunctionTypeName) tname);
		}
		throw new AssertionError("Unrecognized SCTL type kind: " + tname);
	}

	protected static String keyType(AbstractSctlTypeName tname) {
		return PathUtils.makeKey(indexType(tname));
	}

	public static abstract class AbstractRef<T extends SctlTargetNamedDataType<T, ?>>
			implements TargetNamedDataTypeRef<T> {
		protected final SctlTargetDataTypeNamespace types;
		protected final List<String> path;
		protected final AsyncLazyValue<? extends T> t = new AsyncLazyValue<>(this::doGet);

		protected AbstractRef(SctlTargetDataTypeNamespace types, AbstractSctlTypeName tname) {
			this.types = types;
			this.path = PathUtils.index(types.getPath(), SctlTargetNamedDataType.indexType(tname));
		}

		protected abstract CompletableFuture<? extends T> doGet();

		@Override
		public CompletableFuture<? extends T> fetch() {
			return t.request();
		}

		@Override
		public DebuggerObjectModel getModel() {
			return types.client;
		}

		@Override
		public List<String> getPath() {
			return path;
		}
	}

	protected final SctlClient client;
	protected final SctlTargetModule module;

	protected final NamedDataTypeKind kind;

	protected SctlTargetNamedDataType(SctlTargetDataTypeNamespace types,
			AbstractSctlTypeName tname, NamedDataTypeKind kind, String typeHint) {
		super(types.client, types, keyType(tname), typeHint);
		this.client = types.client;
		this.module = types.getImplParent();

		this.kind = kind;

		changeAttributes(List.of(), Map.of( //
			NAMED_DATA_TYPE_KIND_ATTRIBUTE_NAME, kind //
		), "Initialized");
	}

	@Override
	public String toString() {
		return "<" + getClass().getSimpleName() + " " + getIndex() + ">";
	}

	@Override
	public NamedDataTypeKind getKind() {
		return kind;
	}
}
