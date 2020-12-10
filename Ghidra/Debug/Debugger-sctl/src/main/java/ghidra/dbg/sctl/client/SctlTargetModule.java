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

import java.util.*;

import ghidra.async.AsyncLazyMap;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.sctl.protocol.consts.Mkind;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

/**
 * A namespace on the SCTL server
 * 
 * Typically, a namespace belongs to a single target, but it is possible, e.g., if two targets share
 * a common library, for a single namespace to belong to multiple targets. SCTL also generates a
 * namespace on a {@code Tnames} command, which is not associated with any particular CTLID.
 * 
 * The symbols and types from a namespace are cached for the lifetime of this proxy object, because
 * they should never change during the life of the CTLID or NSID. This is accomplished using an
 * {@link AsyncLazyMap}
 */
public class SctlTargetModule
		extends DefaultTargetObject<TargetObject, SctlTargetModuleContainer>
		implements TargetModule<SctlTargetModule> {

	protected static String keyModule(String filepath) {
		return PathUtils.makeKey(indexModule(filepath));
	}

	protected static String indexModule(String filepath) {
		return filepath;
	}

	protected final SctlClient client;
	protected final long nsid;
	protected final String filepath;
	protected final Address base;
	protected AddressRangeImpl range;
	protected final boolean executable;

	protected final SctlTargetSectionContainer sections;
	protected final SctlTargetSymbolNamespace symbols;
	protected final SctlTargetDataTypeNamespace types;

	/**
	 * Construct a module proxy
	 * 
	 * The given path is used as the name of the module.
	 * 
	 * @see SctlClient#createModule(long, String, Address)
	 * @param process the SCTL process to which the namespace belongs
	 * @param nsid the SCTL-assigned nsid "namespace ID"
	 * @param path the path from the {@link Mkind#Tnames} or {@link Mkind#Rstat} message
	 * @param executable true if this is the executable image (not a library)
	 */
	public SctlTargetModule(SctlTargetModuleContainer modules, long nsid, String filepath,
			Address base, boolean executable) {
		super(modules.client, modules, keyModule(filepath), "Module");
		this.client = modules.client;
		this.nsid = nsid;
		this.filepath = filepath;
		this.base = base;
		range = new AddressRangeImpl(base, base);
		this.executable = executable;

		this.sections = new SctlTargetSectionContainer(this);
		this.symbols = new SctlTargetSymbolNamespace(this);
		this.types = new SctlTargetDataTypeNamespace(this);

		changeAttributes(List.of(), Map.of( //
			RANGE_ATTRIBUTE_NAME, range, //
			sections.getName(), sections, //
			symbols.getName(), symbols, //
			types.getName(), types //
		), "Initialized");
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

	protected void addSection(String name, Address start, long length) {
		sections.add(name, start, length);
	}

	public void updateRange() {
		Address max = sections.getCachedElements()
				.values()
				.stream()
				.map(s -> s.getRange().getMaxAddress())
				.max(Comparator.naturalOrder())
				.orElse(null);
		range = new AddressRangeImpl(base, max);
		changeAttributes(List.of(), Map.of(
			RANGE_ATTRIBUTE_NAME, range),
			"Have sections");
	}
}
