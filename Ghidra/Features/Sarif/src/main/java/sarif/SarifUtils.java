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
package sarif;

import java.io.ByteArrayInputStream;
import java.util.*;

import org.bouncycastle.util.encoders.Base64;

import com.contrastsecurity.sarif.*;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class SarifUtils {

	// NB: We're abusing "fullyQualifiedName" and "artifactLocation/uri" here.
	// For our purposes:
	// fullyQualifiedName <= addressSpace name for overlays or non-TYPE_RAM
	// addresses
	// artifactLocation/uri <= the overlayED space name (typically OTHER)

	private static Run currentRun = null;
	// llocs has indexed per run and is not valid across runs
	// Attempts to access llocs outside the population phase will throw an error
	private static LogicalLocation[] llocs;
	// All of the following have keys that are valid across queries
	private static List<com.contrastsecurity.sarif.Address> addresses;
	private static Map<String, Long> nameToOffset = new HashMap<>();
	private static Map<String, LogicalLocation[]> nodeLocs = new HashMap<>();
	private static Map<String, String> edgeSrcs = new HashMap<>();
	private static Map<String, String> edgeDsts = new HashMap<>();
	private static Map<String, Set<String>> edgeDescs = new HashMap<>();
	private static boolean populating = false;

	public static JsonArray setLocations(Address min, Address max) {
		AddressSet set = new AddressSet(min, max);
		return setLocations(set);
	}

	public static JsonArray setLocations(AddressSetView set) {
		JsonArray locations = new JsonArray();
		AddressRangeIterator addressRanges = set.getAddressRanges();
		while (addressRanges.hasNext()) {
			JsonObject element = new JsonObject();
			locations.add(element);
			AddressRange next = addressRanges.next();
			JsonObject ploc = new JsonObject();
			element.add("physicalLocation", ploc);
			JsonObject address = new JsonObject();
			ploc.add("address", address);
			address.addProperty("absoluteAddress", next.getMinAddress().getOffset());
			address.addProperty("length", next.getLength());
			Address minAddress = next.getMinAddress();
			AddressSpace addressSpace = minAddress.getAddressSpace();
			if (!addressSpace.showSpaceName()) {
				continue;
			}

			// type != TYPE_RAM || isOverlaySpace()
			address.addProperty("fullyQualifiedName", addressSpace.getName());
			if (!(addressSpace instanceof OverlayAddressSpace ospace)) {
				continue;
			}

			JsonObject artifact = new JsonObject();
			ploc.add("artifactLocation", artifact);
			String name = ospace.getOverlayedSpace().getName();
			artifact.addProperty("uri", name);
		}
		return locations;
	}

	@SuppressWarnings("unchecked")
	public static AddressSet getLocations(Map<String, Object> result, Program program, AddressSet set)
			throws AddressOverflowException {
		if (set == null) {
			set = new AddressSet();
		}
		List<Location> locations = (List<Location>) result.get("Locations");
		if (locations == null) {
			return set;
		}
		for (Location location : locations) {
			AddressRange range = locationToRange(location, program);
			if (range != null) {
				set.add(range);
			}
		}
		return set;
	}

	public static AddressRange locationToRange(Location location, Program program) throws AddressOverflowException {
		PhysicalLocation physicalLocation = location.getPhysicalLocation();
		long len = physicalLocation.getAddress().getLength();
		Address addr = locationToAddress(location, program, true);
		return addr == null ? null : new AddressRangeImpl(addr, len);
	}

	public static Address locationToAddress(Location location, Program program, boolean useOverlays) {
		if (!populating) {
			throw new RuntimeException("Locations valid only during population phase");
		}
		Long addr = -1L;
		PhysicalLocation physicalLocation = location.getPhysicalLocation();
		if (location.getPhysicalLocation() != null) {
			addr = physicalLocation.getAddress().getAbsoluteAddress();
		}
		if (addr >= 0) {
			AddressFactory af = program.getAddressFactory();
			AddressSpace base = af.getDefaultAddressSpace();

			String fqn = physicalLocation.getAddress().getFullyQualifiedName();
			if (fqn == null) {
				return longToAddress(base, addr);
			}
			if (fqn.equals("NO ADDRESS")) {
				return null;
			}

			ArtifactLocation artifact = physicalLocation.getArtifactLocation();
			if (artifact == null) { // Not an overlay
				AddressSpace space = getAddressSpace(program, fqn, base);
				return longToAddress(space, addr);
			}

			// Overlay
			String uri = artifact.getUri();
			base = program.getAddressFactory().getAddressSpace(uri);
			if (base == null) {
				if (!useOverlays) {
					return longToAddress(af.getDefaultAddressSpace(), addr);
				}
				try {
					base = program.createOverlaySpace(fqn, base);
				} catch (IllegalStateException | DuplicateNameException | InvalidNameException | LockException e) {
					throw new RuntimeException("Attempt to create " + fqn + " failed!");
				}
			}
			AddressSpace space = getAddressSpace(program, fqn, base);
			return longToAddress(space, addr);
		}
		if (location.getLogicalLocations() != null) {
			Set<LogicalLocation> logicalLocations = location.getLogicalLocations();
			for (LogicalLocation logLoc : logicalLocations) {
				if (logLoc.getKind() == null) {
					logLoc = llocs[logLoc.getIndex().intValue()];
				}
				switch (logLoc.getKind()) {
				case "function":
					String fname = logLoc.getName();
					for (Function func : program.getFunctionManager().getFunctions(true)) {
						if (fname.equals(func.getName())) {
							return func.getEntryPoint();
						}
					}
					break;

				case "member":
					// From sarif, we need to extract 2 addrs out of members.
					// The first address is the function entry point.
					return extractFQNameAddrPair(program, logLoc.getFullyQualifiedName()).get(0);

				case "variable":
					// From sarif, we need to extract an addr and a var name.
					// e.g., __buf
					// return the address in the FQN
					return extractFunctionEntryAddr(program, logLoc.getFullyQualifiedName());

				case "instruction":
					break;

				default:
					Msg.error(program, "Unknown logical location to handle: " + logLoc.toString());
				}
			}
		}
		return null;
	}

	private static AddressSpace getAddressSpace(Program program, String fqn, AddressSpace base) {
		AddressSpace space = program.getAddressFactory().getAddressSpace(fqn);
		if (space != null) {
			return space;
		}
		try {
			space = program.createOverlaySpace(fqn, base);
		} catch (IllegalStateException | DuplicateNameException | InvalidNameException | LockException e) {
			throw new RuntimeException("Attempt to create " + fqn + " failed!");
		}
		return space;
	}

	public static Address longToAddress(AddressSpace space, Long addr) {
		return space.getAddressInThisSpaceOnly(addr);
	}

	public static ByteArrayInputStream getArtifactContent(Artifact artifact) {
		ArtifactContent content = artifact.getContents();
		String b64 = content.getBinary();
		byte[] decoded = Base64.decode(b64);
		return new ByteArrayInputStream(decoded);
	}

	public static Address extractFunctionEntryAddr(Program program, String fqname) {
		String addr = null;
		// NB: ! can be used both as a delimiter and part of an operator
		// TODO: This may eventually require a more complicated check
		if (fqname.contains("!") && !fqname.contains("!=")) {
			fqname = fqname.substring(0, fqname.indexOf("!"));
		}
		String[] parts = fqname.split("@");
		if (parts.length > 1) {
			String[] subparts = parts[1].split(":");
			if (subparts[0].equals("EXTERNAL")) {
				try {
					addr = subparts[1];
					return program.getAddressFactory().getAddressSpace(subparts[0]).getAddress(addr);
				} catch (AddressFormatException e) {
					e.printStackTrace();
				}
			}
			addr = subparts[0];
		}
		return program.getAddressFactory().getAddress(addr);
	}

	public static List<Address> extractFQNameAddrPair(Program program, String fqname) {
		List<Address> addr_pair = new ArrayList<Address>();
		String[] parts = fqname.split("@");

		if (parts.length > 1) {
			String[] subparts = parts[1].split(":");
			// subparts: <FN ADDR> , <INSN ADDR>, ???
			if (subparts.length > 1) {
				// This is the function entry point address.
				Address faddress = program.getAddressFactory().getAddress(subparts[0]);
				addr_pair.add(faddress);

				// This is the insn address.
				Address iaddress = program.getAddressFactory().getAddress(subparts[1]);
				addr_pair.add(iaddress != null ? iaddress : faddress);
			} else {
				if (parts[1].contains("!")) {
					subparts = parts[1].split("!");
				}
				Address faddress = program.getAddressFactory().getAddress(subparts[0]);
				addr_pair.add(faddress);
				// This is the insn address.
				addr_pair.add(faddress);
			}
		}

		// could return an empty list.
		// could return a non-empty list with null in it.
		return addr_pair;
	}

	public static String extractFQNameFunction(String fqname) {
		String fname = "UNKNOWN";
		String[] parts = fqname.split("@");
		if (parts.length > 0) {
			fname = parts[0];
		}
		return fname;
	}

	public static String extractDisplayName(LogicalLocation ll) {
		String name = ll.getName();
		String fqname = ll.getFullyQualifiedName();
		if (name != null && name.startsWith("vn")) {
			name = fqname.split("@")[0] + ":" + fqname.split(":")[1];
		} else {
			name = fqname.split("@")[0] + ":" + name;
		}
		return name;
	}

	public static ReportingDescriptor getTaxaValue(ReportingDescriptorReference taxa, ToolComponent taxonomy) {
		List<ReportingDescriptor> view = new ArrayList<>(taxonomy.getTaxa());
		return view.get(taxa.getIndex().intValue());
	}

	public static ToolComponent getTaxonomy(ReportingDescriptorReference taxa, Set<ToolComponent> taxonomies) {
		Object idx = taxa.getToolComponent().getIndex();
		if (idx == null) {
			List<ToolComponent> view = new ArrayList<>(taxonomies);
			idx = taxa.getIndex();
			return view.get(idx instanceof Long ? ((Long) idx).intValue() : (Integer) idx);
		}
		for (ToolComponent taxonomy : taxonomies) {
			if (taxonomy.getName().equals(taxa.getToolComponent().getName())) {
				return taxonomy;
			}
		}
		return null;
	}

	public static List<String> getTaxonomyNames(Run sarifRun) {
		List<String> names = new ArrayList<>();
		Set<ToolComponent> taxonomies = sarifRun.getTaxonomies();
		if (taxonomies != null) {
			for (ToolComponent taxonomy : sarifRun.getTaxonomies()) {
				names.add(taxonomy.getName());
			}
		}
		return names;
	}

	public static LogicalLocation getLogicalLocation(Run run, Location loc) {
		if (!populating) {
			throw new RuntimeException("Locations valid only during population phase");
		}
		Set<LogicalLocation> llocset = loc.getLogicalLocations();
		if (llocset == null) {
			return null;
		}
		Iterator<LogicalLocation> it = llocset.iterator();
		if (it.hasNext()) {
			LogicalLocation next = it.next();
			Long index = next.getIndex();
			if (index != null && llocs != null) {
				return llocs[index.intValue()];
			}
			return next;
		}
		return null;
	}

	public static void validateRun(Run run) {
		initRun(run);
	}

	private static void initRun(Run run) {
		edgeDescs.clear();
		edgeSrcs.clear();
		edgeDsts.clear();
		currentRun = run;
		addresses = run.getAddresses();
		for (com.contrastsecurity.sarif.Address sarifAddr : addresses) {
			Long offset = sarifAddr.getAbsoluteAddress();
			String fqname = sarifAddr.getFullyQualifiedName();
			nameToOffset.put(fqname, offset);
		}
		Set<LogicalLocation> runLocs = run.getLogicalLocations();
		if (runLocs != null) {
			llocs = new LogicalLocation[runLocs.size()];
			runLocs.toArray(llocs);
		}
		Set<Graph> rgraphs = run.getGraphs();
		for (Graph rg : rgraphs) {
			Set<Edge> edges = rg.getEdges();
			for (Edge e : edges) {
				String id = e.getId();
				String src = e.getSourceNodeId();
				String dst = e.getTargetNodeId();
				String desc = e.getLabel().getText();
				edgeSrcs.put(id, src);
				edgeDsts.put(id, dst);
				Set<String> set = edgeDescs.get(desc);
				if (set == null) {
					set = new HashSet<>();
					edgeDescs.put(desc, set);
				}
				set.add(id);
			}
			Set<Node> nodes = rg.getNodes();
			for (Node n : nodes) {
				String id = n.getId();
				Location loc = n.getLocation();
				if (loc != null) {
					Set<LogicalLocation> logicalLocations = loc.getLogicalLocations();
					LogicalLocation[] nodells = new LogicalLocation[logicalLocations.size()];
					int i = 0;
					for (LogicalLocation ll : logicalLocations) {
						// NB: These have to be derefenced immediately as they will be invalid for subsequent queries
						if (ll.getFullyQualifiedName() != null) {
							nodells[i++] = ll;
						}
						else {
							nodells[i++] = llocs[ll.getIndex().intValue()];
						}
					}
					nodeLocs.put(id, nodells);
				}
			}
		}
	}

	public static Set<String> getEdgeSet(String fqname) {
		return edgeDescs.get(fqname);
	}

	public static String getEdgeSource(String edgeId) {
		return edgeSrcs.get(edgeId);
	}

	public static String getEdgeDest(String edgeId) {
		return edgeDsts.get(edgeId);
	}

	public static Address getLocAddress(Program program, String fqname) {
		Long offset = nameToOffset.get(fqname);
		if (offset == null) {
			return null;
		}
		return getAddress(program, offset);
	}

	public static Address getAddress(Program program, Long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	public static LogicalLocation[] getNodeLocs(String id) {
		return nodeLocs.get(id);
	}

	public static void setPopulating(boolean b) {
		populating = b;
	}

	public static Map<String, Set<String>> getEdgeMap() {
		return edgeDescs;
	}

}
