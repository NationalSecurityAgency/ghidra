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
package ghidra.trace.database.guest;

import java.util.*;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathMatcher;
import ghidra.dbg.util.PathPredicates.Align;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.guest.DBTraceGuestPlatform.DBTraceGuestLanguage;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.symbol.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public interface InternalTracePlatform extends TracePlatform {
	String REG_MAP_BE = "__reg_map_be__";
	String REG_MAP_LE = "__reg_map_le__";

	static String regMap(Register register) {
		return register.isBigEndian() ? REG_MAP_BE : REG_MAP_LE;
	}

	/**
	 * Get the entry's key in the table as an integer
	 * 
	 * @return the key
	 */
	int getIntKey();

	DBTraceGuestLanguage getLanguageEntry();

	@Override
	default AddressRange getConventionalRegisterRange(AddressSpace space, Register register) {
		AddressRange result = mapGuestToHost(TraceRegisterUtils.rangeForRegister(register));
		if (result == null) {
			throw new IllegalArgumentException("Register " + register + " is not mapped");
		}
		if (space == null) {
			return result;
		}
		if (register.getAddressSpace().isRegisterSpace()) {
			if (result.getAddressSpace() != space.getPhysicalSpace()) {
				throw new IllegalArgumentException(
					"Register " + register + " does not map to space " + space +
						"'s physical space (" + space.getPhysicalSpace() + ")");
			}
			return new AddressRangeImpl(
				space.getOverlayAddress(result.getMinAddress()),
				space.getOverlayAddress(result.getMaxAddress()));
		}
		if (result.getAddressSpace() != space) {
			throw new IllegalArgumentException(
				"Memory-mapped register " + register + " does not map to space " + space);
		}
		return result;
	}

	default List<String> listRegNames(Register register) {
		Set<String> result = new LinkedHashSet<>();
		result.add(register.getName());
		result.add(register.getName().toUpperCase());
		result.add(register.getName().toLowerCase());
		for (String alias : register.getAliases()) {
			result.add(alias);
			result.add(alias.toUpperCase());
			result.add(alias.toLowerCase());
		}
		return List.copyOf(result);
	}

	@Override
	default Collection<String> getConventionalRegisterObjectNames(Register register) {
		Address pmin = mapGuestToHost(register.getAddress());
		if (pmin == null) {
			return listRegNames(register);
		}
		TraceSymbolManager symbolManager = getTrace().getSymbolManager();
		TraceNamespaceSymbol nsRegMap = symbolManager.namespaces().getGlobalNamed(regMap(register));
		Collection<String> labels = symbolManager.labels()
				.getAt(0, null, pmin, false)
				.stream()
				.filter(s -> s.getParentNamespace() == nsRegMap)
				.map(TraceSymbol::getName)
				.toList();
		if (!labels.isEmpty()) {
			return labels;
		}
		return listRegNames(register);
	}

	@Override
	default PathMatcher getConventionalRegisterPath(TargetObjectSchema schema, List<String> path,
			Collection<String> names) {
		PathMatcher matcher = schema.searchFor(TargetRegister.class, path, true);
		if (matcher.isEmpty()) {
			return matcher;
		}
		PathMatcher result = new PathMatcher();
		for (String name:names) {
			result.addAll(matcher.applyKeys(Align.RIGHT, List.of(name)));
		}
		return result;
	}

	@Override
	default PathMatcher getConventionalRegisterPath(TargetObjectSchema schema, List<String> path,
			Register register) {
		return getConventionalRegisterPath(schema, path,
			getConventionalRegisterObjectNames(register));
	}

	@Override
	default PathMatcher getConventionalRegisterPath(TraceObject container, Register register) {
		return getConventionalRegisterPath(container.getTargetSchema(),
			container.getCanonicalPath().getKeyList(), register);
	}

	@Override
	default PathMatcher getConventionalRegisterPath(TargetObject container, Register register) {
		return getConventionalRegisterPath(container.getSchema(), container.getPath(), register);
	}

	@Override
	default PathMatcher getConventionalRegisterPath(AddressSpace space, Register register) {
		List<String> path = PathUtils.parse(space.getName());
		TargetObjectSchema rootSchema = getTrace().getObjectManager().getRootSchema();
		if (rootSchema == null) {
			return null;
		}
		TargetObjectSchema schema = rootSchema
				.getSuccessorSchema(path);
		return getConventionalRegisterPath(schema, path, register);
	}

	@Override
	default TraceLabelSymbol addRegisterMapOverride(Register register, String objectName) {
		Address hostAddr = mapGuestToHost(register.getAddress());
		if (hostAddr == null) {
			throw new IllegalStateException(
				"Given register is not mapped to the host, or it's not in the guest language");
		}
		try (LockHold hold = getTrace().lockWrite()) {
			TraceSymbolManager symbolManager = getTrace().getSymbolManager();
			TraceNamespaceSymbol globals = symbolManager.getGlobalNamespace();
			TraceNamespaceSymbolView namespaces = symbolManager.namespaces();
			String regMap = regMap(register);
			TraceNamespaceSymbol nsRegMap = namespaces.getGlobalNamed(regMap);
			if (nsRegMap == null) {
				nsRegMap = namespaces.add(regMap, globals, SourceType.USER_DEFINED);
			}
			TraceLabelSymbol exists = symbolManager.labels()
					.getChildWithNameAt(objectName, getIntKey(), null, hostAddr, nsRegMap);
			if (exists != null) {
				return exists;
			}
			return symbolManager.labels()
					.create(0, null, hostAddr, objectName, nsRegMap, SourceType.USER_DEFINED);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			// I checked for the namespace first and with a write lock
			// The input is REG_MAP, which had better be valid
			throw new AssertionError();
		}
	}

	default AddressRange getRegistersRange() {
		Language language = getLanguage();
		AddressSpace regSpace = language.getAddressFactory().getRegisterSpace();
		AddressSetView regAddrs = language.getRegisterAddresses();
		AddressIterator minIt = regAddrs.getAddresses(regSpace.getMinAddress(), true);
		if (!minIt.hasNext()) {
			return null;
		}
		AddressIterator maxIt = regAddrs.getAddresses(regSpace.getMaxAddress(), false);
		return new AddressRangeImpl(minIt.next(), maxIt.next());
	}
}
