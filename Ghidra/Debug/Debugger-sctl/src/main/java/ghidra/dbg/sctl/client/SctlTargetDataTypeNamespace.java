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

import static ghidra.async.AsyncUtils.sequence;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.async.*;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.attributes.*;
import ghidra.dbg.attributes.TargetArrayDataType.DefaultTargetArrayDataType;
import ghidra.dbg.attributes.TargetBitfieldDataType.DefaultTargetBitfieldDataType;
import ghidra.dbg.attributes.TargetPointerDataType.DefaultTargetPointerDataType;
import ghidra.dbg.attributes.TargetPrimitiveDataType.DefaultTargetPrimitiveDataType;
import ghidra.dbg.sctl.protocol.SctlPacket;
import ghidra.dbg.sctl.protocol.common.reply.SctlEnumerateTypesReply;
import ghidra.dbg.sctl.protocol.common.reply.SctlLookupTypeReply;
import ghidra.dbg.sctl.protocol.common.request.SctlEnumerateTypesRequest;
import ghidra.dbg.sctl.protocol.common.request.SctlLookupTypeRequest;
import ghidra.dbg.sctl.protocol.consts.Cbase;
import ghidra.dbg.sctl.protocol.types.*;
import ghidra.dbg.target.TargetDataTypeNamespace;

public class SctlTargetDataTypeNamespace
		extends DefaultTargetObject<SctlTargetNamedDataType<?, ?>, SctlTargetModule>
		implements TargetDataTypeNamespace<SctlTargetDataTypeNamespace> {

	protected static final CompletableFuture<TargetDataType> COMPLETED_TYPE_VOID =
		CompletableFuture.completedFuture(TargetPrimitiveDataType.VOID);

	protected final SctlClient client;

	protected final AsyncLazyMap<AbstractSctlTypeName, SelSctlTypeDefinition> lazyDefs =
		new AsyncLazyMap<>(new HashMap<>(), this::doGetTypeDef);
	protected final AsyncLazyValue<Map<AbstractSctlTypeName, SelSctlTypeDefinition>> allDefs =
		new AsyncLazyValue<>(this::doGetAllTypeDefs);

	protected final AsyncLazyMap<AbstractSctlTypeName, TargetDataType> lazyTypes =
		new AsyncLazyMap<>(new HashMap<>(), this::doGetType);
	protected final AsyncLazyValue<Collection<TargetDataType>> allTypes =
		new AsyncLazyValue<>(this::doGetAllTypes);

	public SctlTargetDataTypeNamespace(SctlTargetModule module) {
		super(module.client, module, "Types", "DataTypeNamespace");
		this.client = module.client;
	}

	public CompletableFuture<SelSctlTypeDefinition> getTypeDef(AbstractSctlTypeName tname) {
		return lazyDefs.get(tname);
	}

	protected CompletableFuture<SelSctlTypeDefinition> doGetTypeDef(AbstractSctlTypeName tname) {
		SctlLookupTypeRequest req = new SctlLookupTypeRequest(parent.nsid, tname);
		return sequence(TypeSpec.cls(SelSctlTypeDefinition.class)).then((seq) -> {
			client.sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishGetTypeDef(req, reply));
		}).finish();
	}

	protected CompletableFuture<SelSctlTypeDefinition> processBusGetTypeDef(int tag,
			SctlLookupTypeRequest req) {
		CompletableFuture<SelSctlTypeDefinition> promise = lazyDefs.put(req.tname.sel);
		return sequence(TypeSpec.cls(SelSctlTypeDefinition.class)).then((seq) -> {
			client.recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			SelSctlTypeDefinition tdef = finishGetTypeDef(req, reply);
			promise.complete(tdef);
			seq.exit(tdef);
		}).finish();
	}

	protected SelSctlTypeDefinition finishGetTypeDef(SctlLookupTypeRequest req,
			SctlPacket reply) {
		SctlLookupTypeReply lookedup = SctlClient.checkReply(req, SctlLookupTypeReply.class, reply);
		return lookedup.tdef;
	}

	protected CompletableFuture<Map<AbstractSctlTypeName, SelSctlTypeDefinition>> doGetAllTypeDefs() {
		SctlEnumerateTypesRequest req = new SctlEnumerateTypesRequest(parent.nsid);
		return sequence(TypeSpec.future(this::doGetAllTypeDefs)).then((seq) -> {
			client.sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishGetAllTypeDefs(req, reply));
		}).finish();
	}

	protected CompletableFuture<Map<AbstractSctlTypeName, SelSctlTypeDefinition>> processBusGetAllTypeDefs(
			int tag, SctlEnumerateTypesRequest req) {
		CompletableFuture<Map<AbstractSctlTypeName, SelSctlTypeDefinition>> promise =
			allDefs.provide();
		return sequence(TypeSpec.future(this::processBusGetAllTypeDefs)).then((seq) -> {
			client.recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			Map<AbstractSctlTypeName, SelSctlTypeDefinition> replies =
				finishGetAllTypeDefs(req, reply);
			promise.complete(replies);
			seq.exit(replies);
		}).finish();
	}

	protected Map<AbstractSctlTypeName, SelSctlTypeDefinition> finishGetAllTypeDefs(
			SctlEnumerateTypesRequest req, SctlPacket reply) {
		SctlEnumerateTypesReply enumed =
			SctlClient.checkReply(req, SctlEnumerateTypesReply.class, reply);
		synchronized (lazyDefs) {
			for (SelSctlTypeDefinition tdef : enumed.tdefs) {
				final AbstractSctlTypeName tname = tdef.getTypeName();
				lazyDefs.put(tname, tdef);
			}
			return lazyDefs.getCompletedMap();
		}
	}

	public CompletableFuture<TargetDataType> getType(AbstractSctlTypeName tname) {
		return lazyTypes.get(tname);
	}

	protected CompletableFuture<TargetDataType> doGetType(AbstractSctlTypeName tname) {
		if (tname instanceof SctlArrayTypeName) {
			SctlArrayTypeName nArray = (SctlArrayTypeName) tname;
			return getType(nArray.tname.sel).thenApply(tElem -> {
				return new DefaultTargetArrayDataType(tElem, (int) nArray.nelem);
			});
		}
		if (tname instanceof SctlBaseTypeName) {
			SctlBaseTypeName tBase = (SctlBaseTypeName) tname;
			if (tBase.base == Cbase.Vvoid) {
				return COMPLETED_TYPE_VOID;
			}
			return getTypeDef(tname).thenApply(d -> {
				SctlBaseTypeDefinition dBase = (SctlBaseTypeDefinition) d.sel;
				return new DefaultTargetPrimitiveDataType(dBase.rep.getKind(),
					dBase.rep.getByteLength());
			});
		}
		if (tname instanceof SctlBitfieldTypeName) {
			SctlBitfieldTypeName nBitfield = (SctlBitfieldTypeName) tname;
			return getType(nBitfield.tname.sel).thenApply(tField -> {
				return new DefaultTargetBitfieldDataType(tField, Byte.toUnsignedInt(nBitfield.pos),
					Byte.toUnsignedInt(nBitfield.width));
			});
		}
		if (tname instanceof SctlEnumConstTypeName) {
			// Just let it take the enum type, perhaps with a "const" modifier, if Ghidra supports it
			SctlEnumConstTypeName nEnumConst = (SctlEnumConstTypeName) tname;
			return getType(nEnumConst.tname.sel).thenApply(tEnum -> {
				return tEnum; // TODO: Some indicator of being constant?
			});
		}
		if (tname instanceof SctlEnumTypeName) {
			SctlEnumTypeName nEnum = (SctlEnumTypeName) tname;
			return CompletableFuture.completedFuture(new SctlTargetEnumDataType.Ref(this, nEnum));
		}
		if (tname instanceof SctlFunctionTypeName) {
			SctlFunctionTypeName nFunction = (SctlFunctionTypeName) tname;
			SctlTargetFunctionDataType tFunction = new SctlTargetFunctionDataType(this, nFunction);
			return tFunction.collectMembers().thenApply(__ -> {
				changeElements(List.of(), List.of(tFunction), "Fetched");
				return tFunction;
			});
		}
		if (tname instanceof SctlPointerTypeName) {
			SctlPointerTypeName nPointer = (SctlPointerTypeName) tname;
			return getType(nPointer.tname.sel).thenApply(tReferent -> {
				return new DefaultTargetPointerDataType(tReferent);
			});
		}
		if (tname instanceof SctlStructTypeName) {
			SctlStructTypeName nStruct = (SctlStructTypeName) tname;
			return CompletableFuture
					.completedFuture(new SctlTargetStructDataType.Ref(this, nStruct));
		}
		if (tname instanceof SctlTypedefTypeName) {
			SctlTypedefTypeName nTypedef = (SctlTypedefTypeName) tname;
			return CompletableFuture
					.completedFuture(new SctlTargetTypedefDataType.Ref(this, nTypedef));
		}
		if (tname instanceof SctlUndefinedTypeName) {
			SctlUndefinedTypeName nUndefined = (SctlUndefinedTypeName) tname;
			// Just pass it through, perhaps with some modifier
			return getType(nUndefined.tname.sel).thenApply(tUndefined -> {
				return tUndefined; // TODO: Some indicator of being undefined?
			});
		}
		if (tname instanceof SctlUnionTypeName) {
			SctlUnionTypeName nUnion = (SctlUnionTypeName) tname;
			return CompletableFuture.completedFuture(new SctlTargetUnionDataType.Ref(this, nUnion));
		}
		throw new AssertionError("Unrecognized SCTL type name: " + tname);
	}

	protected CompletableFuture<Collection<TargetDataType>> doGetAllTypes() {
		return sequence(TypeSpec.future(this::doGetAllTypes)).then(seq -> {
			allDefs.request().handle(seq::next);
		}, TypeSpec.map(AbstractSctlTypeName.class, SelSctlTypeDefinition.class)).then((m, seq) -> {
			AsyncFence fence = new AsyncFence();
			for (AbstractSctlTypeName tname : m.keySet()) {
				fence.include(lazyTypes.get(tname));
			}
			fence.ready().handle(seq::next);
		}).then((seq) -> {
			seq.exit(lazyTypes.getCompletedMap().values());
		}).finish();
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getAllTypes().thenCompose(all -> {
			AsyncFence fence = new AsyncFence();
			// NOTE: Some derived data types get added as we process children of named ones
			for (TargetDataType t : new ArrayList<>(all)) {
				if (t instanceof TargetNamedDataTypeRef<?>) {
					TargetNamedDataTypeRef<?> ref = (TargetNamedDataTypeRef<?>) t;
					fence.include(ref.fetch()); // Get should cause the element to get added
				}
			}
			return fence.ready();
		});
	}

	public CompletableFuture<Collection<TargetDataType>> getAllTypes() {
		return allTypes.request();
	}
}
