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

import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.sctl.client.depr.DebuggerAddressMapper;
import ghidra.dbg.sctl.protocol.common.SctlSymbol;
import ghidra.dbg.sctl.protocol.consts.Stype;
import ghidra.dbg.sctl.protocol.types.SelSctlTypeName;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSymbol;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

/**
 * A symbol retrieved by the SCTL client
 * 
 * Implementation note: The type of the symbol is lazily requested.
 */
public class SctlTargetSymbol extends DefaultTargetObject<TargetObject, SctlTargetSymbolNamespace>
		implements TargetSymbol<SctlTargetSymbol> {

	protected static String keySymbol(SctlSymbol sym) {
		return PathUtils.makeKey(indexSymbol(sym));
	}

	protected static String indexSymbol(SctlSymbol sym) {
		return sym.name.str;
	}

	protected final SctlClient client;

	protected final SctlTargetModule module;
	protected final BitmaskSet<Stype> flags;
	protected final SelSctlTypeName tname;
	protected TargetDataType dataType;
	protected final Address value;
	protected final long size;

	/**
	 * Construct a new symbol description
	 * 
	 * @param module the namespace containing the symbol
	 * @param sym the symbol description from the protocol message
	 * @param mapper the client's address mapper
	 */
	public SctlTargetSymbol(SctlTargetSymbolNamespace symbols, SctlTargetModule module,
			SctlSymbol sym, DebuggerAddressMapper mapper) {
		super(symbols.client, symbols, keySymbol(sym), "Symbol");
		this.client = symbols.client;

		this.module = module;
		this.flags = sym.flags;
		this.tname = sym.tname;
		if (isConstant()) {
			this.value = mapper.getAddressFactory().getConstantAddress(sym.val);
		}
		else {
			this.value = mapper.mapOffsetToAddress(sym.val);
		}
		this.size = sym.size;

		changeAttributes(List.of(), Map.of(
			VALUE_ATTRIBUTE_NAME, value,
			DATA_TYPE_ATTRIBUTE_NAME, dataType,
			SIZE_ATTRIBUTE_NAME, size //
		), "Initialized");
	}

	protected CompletableFuture<SctlTargetSymbol> init() {
		return module.types.getType(tname.sel).thenApply(t -> {
			dataType = t;
			changeAttributes(List.of(), Map.of( //
				DATA_TYPE_ATTRIBUTE_NAME, t //
			), "Initialized");
			return this;
		});
	}

	@Override
	public TargetDataType getDataType() {
		return dataType;
	}

	@Override
	public boolean isConstant() {
		return flags.contains(Stype.Senum);
	}

	@Override
	public Address getValue() {
		return value;
	}

	@Override
	public long getSize() {
		return size;
	}
}
