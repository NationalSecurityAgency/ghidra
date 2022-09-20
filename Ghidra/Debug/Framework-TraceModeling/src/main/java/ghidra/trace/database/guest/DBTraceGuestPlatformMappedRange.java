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

import java.io.IOException;

import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.trace.model.guest.TraceGuestPlatformMappedRange;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceGuestPlatformMappedRange extends DBAnnotatedObject
		implements TraceGuestPlatformMappedRange {
	public static final String TABLE_NAME = "LanguageMappings";

	static final String HOST_SPACE_COLUMN_NAME = "HostSpace";
	static final String HOST_OFFSET_COLUMN_NAME = "HostOffset";
	static final String GUEST_LANGUAGE_COLUMN_NAME = "GuestLanguage";
	static final String GUEST_SPACE_COLUMN_NAME = "GuestSpace";
	static final String GUEST_OFFSET_COLUMN_NAME = "GuestOffset";
	static final String LENGTH_COLUMN_NAME = "Length";

	@DBAnnotatedColumn(HOST_SPACE_COLUMN_NAME)
	static DBObjectColumn HOST_SPACE_COLUMN;
	@DBAnnotatedColumn(HOST_OFFSET_COLUMN_NAME)
	static DBObjectColumn HOST_OFFSET_COLUMN;
	@DBAnnotatedColumn(GUEST_LANGUAGE_COLUMN_NAME)
	static DBObjectColumn GUEST_LANGUAGE_COLUMN;
	@DBAnnotatedColumn(GUEST_SPACE_COLUMN_NAME)
	static DBObjectColumn GUEST_SPACE_COLUMN;
	@DBAnnotatedColumn(GUEST_OFFSET_COLUMN_NAME)
	static DBObjectColumn GUEST_OFFSET_COLUMN;
	@DBAnnotatedColumn(LENGTH_COLUMN_NAME)
	static DBObjectColumn LENGTH_COLUMN;

	@DBAnnotatedField(column = HOST_SPACE_COLUMN_NAME)
	private int hostSpaceID;
	@DBAnnotatedField(column = HOST_OFFSET_COLUMN_NAME)
	private long hostOffset;
	@DBAnnotatedField(column = GUEST_LANGUAGE_COLUMN_NAME)
	int guestPlatformKey;
	@DBAnnotatedField(column = GUEST_SPACE_COLUMN_NAME)
	private int guestSpaceID;
	@DBAnnotatedField(column = GUEST_OFFSET_COLUMN_NAME)
	private long guestOffset;
	@DBAnnotatedField(column = LENGTH_COLUMN_NAME)
	private long length;

	private DBTracePlatformManager manager;

	private AddressRangeImpl hostRange;
	private DBTraceGuestPlatform platform;
	private AddressRangeImpl guestRange;
	private AddressSpace hostSpace;
	private AddressSpace guestSpace;
	private long shiftHostToGuest;

	public DBTraceGuestPlatformMappedRange(DBTracePlatformManager manager, DBCachedObjectStore<?> s,
			DBRecord r) {
		super(s, r);
		this.manager = manager;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}
		this.hostSpace = manager.trace.getBaseAddressFactory().getAddressSpace(hostSpaceID);
		Address hostStart = hostSpace.getAddress(hostOffset);
		Address hostEnd = hostStart.addWrap(length - 1);
		this.hostRange = new AddressRangeImpl(hostStart, hostEnd);

		InternalTracePlatform platform = manager.getPlatformByKey(guestPlatformKey);
		if (platform.isHost()) {
			throw new IOException("Table is corrupt. Got host platform in guest mapping.");
		}
		this.platform = (DBTraceGuestPlatform) platform;
		this.guestSpace = platform.getAddressFactory().getAddressSpace(guestSpaceID);
		Address guestStart = guestSpace.getAddress(guestOffset);
		Address guestEnd = guestStart.addWrap(length - 1);
		this.guestRange = new AddressRangeImpl(guestStart, guestEnd);

		this.shiftHostToGuest = guestStart.getOffset() - hostStart.getOffset();
	}

	void set(Address hostStart, DBTraceGuestPlatform platform, Address guestStart, long length) {
		this.hostSpace = hostStart.getAddressSpace();
		this.hostSpaceID = hostSpace.getSpaceID();
		this.hostOffset = hostStart.getOffset();
		this.guestPlatformKey = (int) platform.getKey();
		this.guestSpace = guestStart.getAddressSpace();
		this.guestSpaceID = guestSpace.getSpaceID();
		this.guestOffset = guestStart.getOffset();
		this.length = length;
		update(HOST_SPACE_COLUMN, HOST_OFFSET_COLUMN, GUEST_LANGUAGE_COLUMN, GUEST_SPACE_COLUMN,
			GUEST_OFFSET_COLUMN, LENGTH_COLUMN);

		this.hostRange = new AddressRangeImpl(hostStart, hostStart.addWrap(length - 1));
		this.platform = platform;
		this.guestRange = new AddressRangeImpl(guestStart, guestStart.addWrap(length - 1));

		this.shiftHostToGuest = guestStart.getOffset() - hostStart.getOffset();
	}

	@Override
	public InternalTracePlatform getHostPlatform() {
		return manager.hostPlatform;
	}

	@Override
	public AddressRange getHostRange() {
		return hostRange;
	}

	@Override
	public DBTraceGuestPlatform getGuestPlatform() {
		return platform;
	}

	@Override
	public AddressRange getGuestRange() {
		return guestRange;
	}

	protected static Address doMapTo(Address address, AddressSpace space, long shift) {
		return space.getAddress(address.getOffset() + shift);
	}

	protected static AddressRange doMapTo(AddressRange range, AddressSpace space, long shift) {
		return new AddressRangeImpl(
			doMapTo(range.getMinAddress(), space, shift),
			doMapTo(range.getMaxAddress(), space, shift));
	}

	@Override
	public Address mapHostToGuest(Address hostAddress) {
		if (!hostRange.contains(hostAddress)) {
			return null;
		}
		return doMapTo(hostAddress, guestSpace, shiftHostToGuest);
	}

	@Override
	public AddressRange mapHostToGuest(AddressRange hostRange) {
		if (!this.hostRange.contains(hostRange.getMinAddress()) ||
			!this.hostRange.contains(hostRange.getMaxAddress())) {
			return null;
		}
		return doMapTo(hostRange, guestSpace, shiftHostToGuest);
	}

	@Override
	public Address mapGuestToHost(Address guestAddress) {
		if (!guestRange.contains(guestAddress)) {
			return null;
		}
		return doMapTo(guestAddress, hostSpace, -shiftHostToGuest);
	}

	@Override
	public AddressRange mapGuestToHost(AddressRange guestRange) {
		if (!this.guestRange.contains(guestRange.getMinAddress()) ||
			!this.guestRange.contains(guestRange.getMaxAddress())) {
			return null;
		}
		return doMapTo(guestRange, hostSpace, -shiftHostToGuest);
	}

	@Override
	public void delete(TaskMonitor monitor) throws CancelledException {
		platform.deleteMappedRange(this, monitor);
	}
}
