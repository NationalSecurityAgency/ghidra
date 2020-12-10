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
import ghidra.dbg.sctl.protocol.SctlPacket;
import ghidra.dbg.sctl.protocol.common.SctlSymbol;
import ghidra.dbg.sctl.protocol.common.reply.SctlEnumerateSymbolsReply;
import ghidra.dbg.sctl.protocol.common.reply.SctlLookupSymbolReply;
import ghidra.dbg.sctl.protocol.common.request.SctlEnumerateSymbolsRequest;
import ghidra.dbg.sctl.protocol.common.request.SctlLookupSymbolRequest;
import ghidra.dbg.target.TargetSymbolNamespace;

public class SctlTargetSymbolNamespace
		extends DefaultTargetObject<SctlTargetSymbol, SctlTargetModule>
		implements TargetSymbolNamespace<SctlTargetSymbolNamespace> {

	protected final SctlClient client;

	private final AsyncLazyMap<String, SctlTargetSymbol> lazySymbols =
		new AsyncLazyMap<>(new HashMap<>(), this::doGetSymbol);
	private final AsyncLazyValue<Map<String, SctlTargetSymbol>> allSymbols =
		new AsyncLazyValue<>(this::doGetAllSymbols);

	public SctlTargetSymbolNamespace(SctlTargetModule module) {
		super(module.client, module, "Symbols", "SymbolNamespace");
		this.client = module.client;
	}

	public CompletableFuture<SctlTargetSymbol> getSymbol(String name) {
		return lazySymbols.get(name);
	}

	protected CompletableFuture<SctlTargetSymbol> doGetSymbol(String name) {
		SctlLookupSymbolRequest req = new SctlLookupSymbolRequest(parent.nsid, name);
		return sequence(TypeSpec.cls(SctlTargetSymbol.class)).then((seq) -> {
			client.sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			SctlTargetSymbol sym = finishGetSymbol(req, reply);
			sym.init().handle(seq::exit);
		}).finish();
	}

	protected CompletableFuture<SctlTargetSymbol> processBusGetSymbol(int tag,
			SctlLookupSymbolRequest req) {
		CompletableFuture<SctlTargetSymbol> promise = lazySymbols.put(req.name.str);
		return sequence(TypeSpec.cls(SctlTargetSymbol.class)).then((seq) -> {
			client.recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			SctlTargetSymbol sym = finishGetSymbol(req, reply);
			sym.init().handle(seq::next);
		}, TypeSpec.cls(SctlTargetSymbol.class)).then((sym, seq) -> {
			promise.complete(sym);
			seq.exit(sym);
		}).finish();
	}

	protected SctlTargetSymbol finishGetSymbol(SctlLookupSymbolRequest req, SctlPacket reply) {
		SctlLookupSymbolReply lookedup =
			SctlClient.checkReply(req, SctlLookupSymbolReply.class, reply);
		SctlTargetSymbol sym = new SctlTargetSymbol(this, parent, lookedup.sym, client.addrMapper);
		changeElements(List.of(), List.of(sym), "Fetched");
		return sym;
	}

	/*
	 * Methods for Tenumsym
	 */

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		if (refresh) {
			allSymbols.forget();
			lazySymbols.clear();
		}
		return allSymbols.request().thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<SctlTargetSymbol> fetchElement(String index) {
		return lazySymbols.get(index);
	}

	private CompletableFuture<Map<String, SctlTargetSymbol>> doGetAllSymbols() {
		SctlEnumerateSymbolsRequest req = new SctlEnumerateSymbolsRequest(parent.nsid);
		return sequence(TypeSpec.map(String.class, SctlTargetSymbol.class)).then((seq) -> {
			client.sendCommand(req).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			seq.exit(finishGetAllSymbols(req, reply));
		}).finish();
	}

	CompletableFuture<Map<String, SctlTargetSymbol>> processBusGetAllSymbols(int tag,
			SctlEnumerateSymbolsRequest req) {
		CompletableFuture<Map<String, SctlTargetSymbol>> promise = allSymbols.provide();
		return sequence(TypeSpec.map(String.class, SctlTargetSymbol.class)).then((seq) -> {
			client.recvTag(tag).handle(seq::next);
		}, TypeSpec.cls(SctlPacket.class)).then((reply, seq) -> {
			Map<String, SctlTargetSymbol> syms = finishGetAllSymbols(req, reply);
			promise.complete(syms);
			seq.exit(syms);
		}).finish();
	}

	Map<String, SctlTargetSymbol> finishGetAllSymbols(SctlEnumerateSymbolsRequest req,
			SctlPacket reply) {
		SctlEnumerateSymbolsReply enumed =
			SctlClient.checkReply(req, SctlEnumerateSymbolsReply.class, reply);
		synchronized (lazySymbols) {
			for (SctlSymbol sym : enumed.syms) {
				SctlTargetSymbol symbol =
					new SctlTargetSymbol(this, parent, sym, client.addrMapper);
				lazySymbols.put(sym.name.str, symbol);
			}
		}
		Map<String, SctlTargetSymbol> result = lazySymbols.getCompletedMap();
		changeElements(List.of(), result.values(), "Fetched");
		return result;
	}
}
