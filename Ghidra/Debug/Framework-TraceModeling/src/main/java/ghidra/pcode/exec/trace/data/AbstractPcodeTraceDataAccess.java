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
package ghidra.pcode.exec.trace.data;

import java.nio.ByteBuffer;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceTimeViewport;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.*;
import ghidra.trace.util.TraceRegisterUtils;

/**
 * An abstract data-access shim, for either memory or registers
 */
public abstract class AbstractPcodeTraceDataAccess implements InternalPcodeTraceDataAccess {
	protected final TracePlatform platform;
	protected final long snap;
	protected final TraceTimeViewport viewport;

	protected final TraceMemoryManager mm;

	/**
	 * Construct a shim
	 * 
	 * @param platform the associated platform
	 * @param snap the associated snap
	 * @param viewport the viewport, set to the same snapshot
	 */
	public AbstractPcodeTraceDataAccess(TracePlatform platform, long snap,
			TraceTimeViewport viewport) {
		this.platform = platform;
		this.snap = snap;
		this.viewport = viewport;

		this.mm = platform.getTrace().getMemoryManager();
	}

	@Override
	public TraceTimeViewport getViewport() {
		return viewport;
	}

	@Override
	public Language getLanguage() {
		return platform.getLanguage();
	}

	@Override
	public TracePlatform getPlatform() {
		return platform;
	}

	@Override
	public long getSnap() {
		return snap;
	}

	/**
	 * Get the interface for accessing trace memory or registers
	 * 
	 * @param createIfAbsent in the case of registers, whether to create the missing space
	 * @return the operations, or null
	 */
	protected abstract TraceMemoryOperations getMemoryOps(boolean createIfAbsent);

	/**
	 * If this shim is associated with a (register) overlay space, translate the given address into
	 * it
	 * 
	 * @param address the physical (register) address
	 * @return the overlay address
	 */
	protected abstract Address toOverlay(Address address);

	/**
	 * @see #toOverlay(Address)
	 * @param range the physical range
	 * @return the overlay range
	 */
	protected abstract AddressRange toOverlay(AddressRange range);

	/**
	 * @see #toOverlay(Address)
	 * @param set
	 * @return
	 */
	protected abstract AddressSetView toOverlay(AddressSetView set);

	@Override
	public void setState(AddressRange guestRange, TraceMemoryState state) {
		AddressRange hostRange = platform.mapGuestToHost(guestRange);
		if (hostRange == null) {
			return;
		}
		getMemoryOps(true).setState(snap, toOverlay(hostRange), state);
	}

	@Override
	public TraceMemoryState getViewportState(AddressRange guestRange) {
		TraceMemoryOperations ops = getMemoryOps(false);
		if (ops == null) {
			return TraceMemoryState.UNKNOWN;
		}

		AddressRange hostRange = platform.mapGuestToHost(guestRange);
		if (hostRange == null) {
			return TraceMemoryState.UNKNOWN;
		}

		AddressSet hostSet = new AddressSet(toOverlay(hostRange));
		for (long snap : viewport.getOrderedSnaps()) {
			hostSet.delete(
				ops.getAddressesWithState(snap, hostSet, s -> s == TraceMemoryState.KNOWN));
		}
		return hostSet.isEmpty() ? TraceMemoryState.KNOWN : TraceMemoryState.UNKNOWN;
	}

	@Override
	public AddressSetView intersectViewKnown(AddressSetView guestView, boolean useFullSpans) {
		TraceMemoryOperations ops = getMemoryOps(false);
		if (ops == null) {
			return new AddressSet();
		}

		AddressSetView hostView = toOverlay(platform.mapGuestToHost(guestView));
		AddressSet hostKnown = new AddressSet();
		if (useFullSpans) {
			for (Lifespan span : viewport.getOrderedSpans()) {
				hostKnown.add(ops.getAddressesWithState(span, hostView,
					st -> st != null && st != TraceMemoryState.UNKNOWN));
			}
		}
		else {
			for (long snap : viewport.getOrderedSnaps()) {
				hostKnown.add(ops.getAddressesWithState(snap, hostView,
					st -> st != null && st != TraceMemoryState.UNKNOWN));
			}
		}
		AddressSetView hostResult =
			TraceRegisterUtils.getPhysicalSet(hostView.intersect(hostKnown));
		return platform.mapHostToGuest(hostResult);
	}

	@Override
	public AddressSetView intersectUnknown(AddressSetView guestView) {
		TraceMemoryOperations ops = getMemoryOps(false);
		if (ops == null) {
			return guestView;
		}

		AddressSetView hostView = toOverlay(platform.mapGuestToHost(guestView));
		AddressSetView hostKnown = ops.getAddressesWithState(snap, hostView,
			s -> s != null && s != TraceMemoryState.UNKNOWN);
		AddressSetView hostResult = TraceRegisterUtils.getPhysicalSet(hostView.subtract(hostKnown));
		return platform.mapHostToGuest(hostResult);
	}

	@Override
	public int putBytes(Address start, ByteBuffer buf) {
		// TODO: Truncate or verify range?
		Address hostStart = platform.mapGuestToHost(start);
		if (hostStart == null) {
			return 0;
		}
		return getMemoryOps(true).putBytes(snap, toOverlay(hostStart), buf);
	}

	@Override
	public int getBytes(Address start, ByteBuffer buf) {
		// TODO: Truncate or verify range?
		Address hostStart = platform.mapGuestToHost(start);
		if (hostStart == null) {
			return 0;
		}
		TraceMemoryOperations ops = getMemoryOps(false);
		if (ops == null) {
			// TODO: Write 0s?
			int length = buf.remaining();
			buf.position(buf.position() + length);
			return length;
		}
		return ops.getViewBytes(snap, toOverlay(hostStart), buf);
	}

	@Override
	public Address translate(Address address) {
		Address host = platform.mapGuestToHost(address);
		if (host == null) {
			return null;
		}
		return toOverlay(host);
	}

	@Override
	public <T> PcodeTracePropertyAccess<T> getPropertyAccess(String name, Class<T> type) {
		return new DefaultPcodeTracePropertyAccess<>(this, name, type);
	}
}
