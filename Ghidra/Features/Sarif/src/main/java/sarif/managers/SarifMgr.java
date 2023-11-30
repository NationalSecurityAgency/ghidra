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
package sarif.managers;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.contrastsecurity.sarif.ArtifactLocation;
import com.contrastsecurity.sarif.Location;
import com.contrastsecurity.sarif.PhysicalLocation;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;

public abstract class SarifMgr {

	protected static final Boolean USE_SARIF = true;

	protected String key;
	static protected Map<String, Boolean> columnKeys = new HashMap<>();
	protected Program program;
	protected Listing listing;
	protected AddressFactory factory;
	protected static Map<String, ExternalLocation> externalMap;
	protected boolean firstPass = true;

	protected MessageLog log = new MessageLog() {
		@Override
		public void appendException(Throwable t) {
			appendMsg(t.toString());
		}
	};

	public SarifMgr(String key, Program program, MessageLog log) {
		this.key = key;
		this.program = program;
		this.listing = program.getListing();
		this.factory = program.getAddressFactory();
		this.log = log;
		columnKeys.put("name", false);
		columnKeys.put("location", true);
		columnKeys.put("kind", false);
		columnKeys.put("type", true);
		columnKeys.put("value", false);
		columnKeys.put("size", true);
		columnKeys.put("comment", true);
		columnKeys.put("typeName", true);
		columnKeys.put("typeLocation", true);
	}

	protected void writeLocation(JsonObject result, Address start, Address end) {
		JsonArray locs = new JsonArray();
		result.add("locations", locs);
		JsonObject element = new JsonObject();
		locs.add(element);
		JsonObject ploc = new JsonObject();
		element.add("physicalLocation", ploc);
		JsonObject address = new JsonObject();
		ploc.add("address", address);
		address.addProperty("absoluteAddress", start.getOffset());
		if (end != null) {
			address.addProperty("length", end.subtract(start) + 1);
			if (!start.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) {
				JsonObject artifact = new JsonObject();
				ploc.add("artifactLocation", artifact);
				artifact.addProperty("uri", start.toString());
			}
		}
	}

	protected void writeLocations(JsonObject result, AddressSetView set) {
		JsonArray locs = new JsonArray();
		result.add("locations", locs);
		AddressRangeIterator addressRanges = set.getAddressRanges();
		while (addressRanges.hasNext()) {
			JsonObject element = new JsonObject();
			locs.add(element);
			AddressRange next = addressRanges.next();
			JsonObject ploc = new JsonObject();
			element.add("physicalLocation", ploc);
			JsonObject address = new JsonObject();
			ploc.add("address", address);
			address.addProperty("absoluteAddress", next.getMinAddress().getOffset());
			address.addProperty("length", next.getLength());
			Address minAddress = next.getMinAddress();
			if (!minAddress.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) {
				JsonObject artifact = new JsonObject();
				ploc.add("artifactLocation", artifact);
				artifact.addProperty("uri", minAddress.toString());
			}
		}
	}

	@SuppressWarnings("unchecked")
	protected AddressSet getLocations(Map<String, Object> result, AddressSet set) throws AddressOverflowException {
		if (set == null) {
			set = new AddressSet();
		}
		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		String namespace = (String) result.get("location");
		if (namespace != null) {
			boolean isExternal = namespace.contains("<EXTERNAL>");
			if (isExternal) {
				space = af.getAddressSpace("EXTERNAL");
			}
		}
		String ospace = (String) result.get("overlayedSpace");
		if (ospace != null) {
			space = af.getAddressSpace(ospace);
		}
		List<Location> locations = (List<Location>) result.get("Locations");
		if (locations == null) {
			return set;
		}
		for (Location location : locations) {
			PhysicalLocation physicalLocation = location.getPhysicalLocation();
			Object addr = physicalLocation.getAddress().getAbsoluteAddress();
			Address address = longToAddress(space, addr);
			long len = (long) physicalLocation.getAddress().getLength();
			ArtifactLocation artifact = physicalLocation.getArtifactLocation();
			if (artifact != null) {
				String uri = artifact.getUri();
				if (uri != null) {
					Address test = program.getAddressFactory().getAddress(uri);
					if (test != null) {
						address = test;
					}
				}
			}
			set.add(new AddressRangeImpl(address, len));
		}
		return set;
	}

	protected Address getLocation(Map<String, Object> result) throws AddressOverflowException {
		AddressSet set = new AddressSet();
		getLocations(result, set);
		return set.getMinAddress();
	}

	protected void readResults(List<Map<String, Object>> list, SarifProgramOptions options, TaskMonitor monitor)
			throws AddressFormatException, CancelledException {
		if (list != null) {
			monitor.setMessage("Processing " + key + "...");
			monitor.setMaximum(list.size());
			for (Map<String, Object> result : list) {
				read(result, options, monitor);
				monitor.increment();
			}
		} else {
			monitor.setMessage("Skipping over " + key + " ...");
		}
	}

	public abstract boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws AddressFormatException, CancelledException;

	public String getKey() {
		return key;
	}

	protected Namespace walkNamespace(Namespace parent, String namespace, Address addr, SourceType sourceType,
			Boolean isClass) throws IOException {
		int sep = namespace.indexOf("::");
		if (sep <= 0) {
			return parent;
		}
		String tag = namespace.substring(0, sep);
		if (addr != null) {
			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func != null) {
				if (func.getName(true).equals(tag)) {
					return walkNamespace(func, namespace.substring(sep + 2), addr, sourceType, isClass);
				}
			} else if (tag.startsWith("FUN_")) {
				return null; // Defer this until later
			}
		}

		Namespace child = program.getSymbolTable().getNamespace(tag, parent);
		if (child == null) {
			try {
				if (isClass != null && isClass) {
					child = program.getSymbolTable().createClass(parent, tag, sourceType);
				} else {
					child = NamespaceUtils.createNamespaceHierarchy(tag, parent, program, sourceType);
				}
			} catch (InvalidInputException | DuplicateNameException e) {
				throw new IOException("Error creating namespace for " + tag);
			}
		}
		return walkNamespace(child, namespace.substring(sep + 2), addr, sourceType, isClass);
	}

	protected SourceType getSourceType(String signatureSource) {
		SourceType sourceType = SourceType.IMPORTED;
		if (signatureSource == null) {
			return sourceType;
		}
		try {
			if (signatureSource != null) {
				sourceType = SourceType.valueOf(signatureSource);
			}
		} catch (IllegalArgumentException iae) {
			log.appendMsg("Unknown SourceType: " + signatureSource);
		}
		return sourceType;
	}

	public static Map<String, Boolean> getColumnKeys() {
		return columnKeys;
	}

	public static Address parseAddress(AddressFactory factory, String addrString) {
		if (addrString == null) {
			return null;
		}
		Address addr = factory.getAddress(addrString);
		if (addr == null) {
			int index = addrString.indexOf("::");
			if (index > 0) {
				addr = factory.getAddress(addrString.substring(index + 2));
			}
		}
		return addr;
	}

	public static long parseLong(String longStr) {
		boolean isNegative = longStr.startsWith("-");
		if (isNegative) {
			longStr = longStr.substring(1);
		}
		int radix = 10;
		if (longStr.startsWith("0x")) {
			longStr = longStr.substring(2);
			radix = 16;
		}
		long val = (radix == 10) ? NumericUtilities.parseLong(longStr) : NumericUtilities.parseHexLong(longStr);
		if (isNegative) {
			val *= -1;
		}
		return val;
	}

	private static final String LESS_THAN = "&lt;";
	private static final String GREATER_THAN = "&gt;";
	private static final String APOSTROPHE = "&apos;";
	private static final String QUOTE = "&quot;";
	private static final String AMPERSAND = "&amp;";

	private static final Pattern HEX_DIGIT_PATTERN = Pattern.compile("[&][#][x]([\\da-fA-F]+)[;]");

	public static String unEscapeElementEntities(String escapedSARIFString) {

		Matcher matcher = HEX_DIGIT_PATTERN.matcher(escapedSARIFString);
		StringBuilder buffy = new StringBuilder();
		while (matcher.find()) {
			int codePoint = Integer.parseInt(matcher.group(1), 16);
			matcher.appendReplacement(buffy, Character.toString(codePoint));
		}
		matcher.appendTail(buffy);

		String unescapedStr = buffy.toString();

		unescapedStr = unescapedStr.replaceAll(LESS_THAN, "<");
		unescapedStr = unescapedStr.replaceAll(GREATER_THAN, ">");
		unescapedStr = unescapedStr.replaceAll(APOSTROPHE, "'");
		unescapedStr = unescapedStr.replaceAll(QUOTE, "\"");
		unescapedStr = unescapedStr.replaceAll(AMPERSAND, "&");

		return unescapedStr;
	}

	public Address longToAddress(AddressSpace space, Object addr) {
		if (addr instanceof Long) {
			return space.getAddress((Long) addr);
		}
		return space.getAddress((Integer) addr);
	}

}
