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
package ghidra.trace.database.module;

import java.io.IOException;
import java.net.URL;
import java.util.Objects;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.DBTraceUtils.URLDBFieldCodec;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.AddressDBFieldCodec;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceStaticMapping extends DBAnnotatedObject
		implements TraceStaticMapping, DecodesAddresses {
	public static final String TABLE_NAME = "StaticMappings";

	protected static String parseSpace(String addrStr) {
		String[] parts = addrStr.split(":");
		if (parts.length == 1) {
			return null;
		}
		if (parts.length == 2) {
			return parts[0];
		}
		throw new IllegalArgumentException("Address string should have at most one colon (:)");
	}

	protected static long parseOffset(String addrStr) {
		String[] parts = addrStr.split(":");
		assert parts.length <= 2;
		return Long.parseUnsignedLong(parts[parts.length - 1], 16); // TODO: Use BigInteger?
	}

	static final String TRACE_ADDRESS_COLUMN_NAME = "TraceAddress";
	static final String LENGTH_COLUMN_NAME = "Length";
	static final String START_SNAP_COLUMN_NAME = "StartSnap";
	static final String END_SNAP_COLUMN_NAME = "EndSnap";
	static final String STATIC_PROGRAM_COLUMN_NAME = "StaticProgram";
	static final String STATIC_ADDRESS_COLUMN_NAME = "StaticAddress";

	@DBAnnotatedColumn(TRACE_ADDRESS_COLUMN_NAME)
	static DBObjectColumn TRACE_ADDRESS_COLUMN;
	@DBAnnotatedColumn(LENGTH_COLUMN_NAME)
	static DBObjectColumn LENGTH_COLUMN;
	@DBAnnotatedColumn(START_SNAP_COLUMN_NAME)
	static DBObjectColumn START_SNAP_COLUMN;
	@DBAnnotatedColumn(END_SNAP_COLUMN_NAME)
	static DBObjectColumn END_SNAP_COLUMN;
	@DBAnnotatedColumn(STATIC_PROGRAM_COLUMN_NAME)
	static DBObjectColumn STATIC_PROGRAM_COLUMN;
	@DBAnnotatedColumn(STATIC_ADDRESS_COLUMN_NAME)
	static DBObjectColumn STATIC_ADDRESS_COLUMN;

	@DBAnnotatedField(
		column = TRACE_ADDRESS_COLUMN_NAME,
		indexed = true,
		codec = AddressDBFieldCodec.class)
	private Address traceAddress;
	@DBAnnotatedField(column = LENGTH_COLUMN_NAME)
	private long length;
	@DBAnnotatedField(column = START_SNAP_COLUMN_NAME)
	private long startSnap;
	@DBAnnotatedField(column = END_SNAP_COLUMN_NAME)
	private long endSnap;
	@DBAnnotatedField(column = STATIC_PROGRAM_COLUMN_NAME, codec = URLDBFieldCodec.class)
	private URL staticProgramURL;
	@DBAnnotatedField(column = STATIC_ADDRESS_COLUMN_NAME)
	private String staticAddress;

	private final DBTraceStaticMappingManager manager;

	private AddressRange traceRange;
	private long shift;
	private Range<Long> lifespan;

	public DBTraceStaticMapping(DBTraceStaticMappingManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		if (created) {
			return;
		}
		try {
			this.traceRange =
				new AddressRangeImpl(traceAddress, traceAddress.addNoWrap(length - 1));
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
		this.shift = traceAddress.getOffset() - parseOffset(staticAddress);
		this.lifespan = DBTraceUtils.toRange(startSnap, endSnap);
	}

	void set(AddressRange traceRange, Range<Long> lifespan, URL staticProgramURL,
			String staticAddress) {
		if (startSnap == -1) {
			throw new IllegalArgumentException("endpoint cannot be -1");
		}
		this.traceRange = traceRange;
		this.traceAddress = traceRange.getMinAddress();
		this.length = traceRange.getLength();
		this.lifespan = lifespan;
		this.startSnap = DBTraceUtils.lowerEndpoint(lifespan);
		this.endSnap = DBTraceUtils.upperEndpoint(lifespan);
		this.staticProgramURL = staticProgramURL;
		this.staticAddress = staticAddress;
		update(TRACE_ADDRESS_COLUMN, LENGTH_COLUMN, START_SNAP_COLUMN, END_SNAP_COLUMN,
			STATIC_PROGRAM_COLUMN, STATIC_ADDRESS_COLUMN);

		this.shift = traceAddress.getOffset() - parseOffset(staticAddress);
	}

	@Override
	public DBTraceOverlaySpaceAdapter getOverlaySpaceAdapter() {
		return manager.overlayAdapter;
	}

	@Override
	public Trace getTrace() {
		return manager.trace;
	}

	@Override
	public AddressRange getTraceAddressRange() {
		return traceRange;
	}

	@Override
	public Address getMinTraceAddress() {
		return traceAddress;
	}

	@Override
	public Address getMaxTraceAddress() {
		return traceRange.getMaxAddress();
	}

	@Override
	public long getLength() {
		return length;
	}

	@Override
	public long getShift() {
		return shift;
	}

	@Override
	public Range<Long> getLifespan() {
		return lifespan;
	}

	@Override
	public long getStartSnap() {
		return startSnap;
	}

	@Override
	public long getEndSnap() {
		return endSnap;
	}

	@Override
	public URL getStaticProgramURL() {
		return staticProgramURL;
	}

	@Override
	public String getStaticAddress() {
		return staticAddress;
	}

	@Override
	public void delete() {
		manager.delete(this);
	}

	@Override
	@SuppressWarnings("hiding")
	public boolean conflictsWith(AddressRange range, Range<Long> lifespan, URL toProgramURL,
			String toAddress) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			// Must overlap to conflict
			if (!traceRange.intersects(range)) {
				return false;
			}
			if (!DBTraceUtils.intersect(this.lifespan, lifespan)) {
				return false;
			}

			/**
			 * NOTE: We can't validate the "to" address, because we should not open the program
			 * here. Nevertheless, we need to validate conflicts at the trace database level, not
			 * the service level. We can at least check for matched address space (by name) and
			 * agreement in offset.
			 */
			if (!Objects.equals(this.staticProgramURL, toProgramURL)) {
				return true;
			}

			String thisToSpace = parseSpace(this.staticAddress);
			String thatToSpace = parseSpace(toAddress);
			if (!Objects.equals(thisToSpace, thatToSpace)) {
				return true;
			}

			long thisToOffset = parseOffset(this.staticAddress);
			long thatToOffset = parseOffset(toAddress);
			long toOffsetDiff = thisToOffset - thatToOffset;

			// TODO: Check that this operates at the byte level, not addressable words
			long thisFromOffset = this.traceRange.getMinAddress().getOffset();
			long thatFromOffset = range.getMinAddress().getOffset();
			long fromOffsetDiff = thisFromOffset - thatFromOffset;

			if (toOffsetDiff != fromOffsetDiff) {
				return true;
			}

			return false;
		}
	}
}
