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
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

public class SarifUtils {

	// NB: We're abusing "fullyQualifiedName" and "artifactLocation/uri" here.
	// For our purposes:
	// fullyQualifiedName <= addressSpace name for overlays or non-TYPE_RAM
	// addresses
	// artifactLocation/uri <= the overlayED space name (typically OTHER)

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
	public static AddressSet getLocations(Map<String, Object> result, Program program,
			AddressSet set) throws AddressOverflowException {
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

	public static AddressRange locationToRange(Location location, Program program)
			throws AddressOverflowException {
		PhysicalLocation physicalLocation = location.getPhysicalLocation();
		long len = physicalLocation.getAddress().getLength();
		Address addr = locationToAddress(location, program);
		return addr == null ? null : new AddressRangeImpl(addr, len);
	}

	public static Address locationToAddress(Location location, Program program) {
		if (location.getPhysicalLocation() != null) {
			AddressFactory af = program.getAddressFactory();
			AddressSpace base = af.getDefaultAddressSpace();

			PhysicalLocation physicalLocation = location.getPhysicalLocation();
			Long addr = physicalLocation.getAddress().getAbsoluteAddress();
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
				try {
					base = program.createOverlaySpace(fqn, base);
				}
				catch (IllegalStateException | DuplicateNameException | InvalidNameException
						| LockException e) {
					throw new RuntimeException("Attempt to create " + fqn + " failed!");
				}
			}
			AddressSpace space = getAddressSpace(program, fqn, base);
			return longToAddress(space, addr);
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
		}
		catch (IllegalStateException | DuplicateNameException | InvalidNameException
				| LockException e) {
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

	public static ReportingDescriptor getTaxaValue(ReportingDescriptorReference taxa,
			ToolComponent taxonomy) {
		List<ReportingDescriptor> view = new ArrayList<>(taxonomy.getTaxa());
		return view.get(taxa.getIndex().intValue());
	}

	public static ToolComponent getTaxonomy(ReportingDescriptorReference taxa,
			Set<ToolComponent> taxonomies) {
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

}
