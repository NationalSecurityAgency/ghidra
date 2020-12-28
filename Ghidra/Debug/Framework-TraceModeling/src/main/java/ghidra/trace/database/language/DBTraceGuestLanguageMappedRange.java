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
package ghidra.trace.database.language;

import java.io.IOException;

import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.language.TraceGuestLanguageMappedRange;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceGuestLanguageMappedRange extends DBAnnotatedObject
		implements TraceGuestLanguageMappedRange {
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
	private int hostSpace;
	@DBAnnotatedField(column = HOST_OFFSET_COLUMN_NAME)
	private long hostOffset;
	@DBAnnotatedField(column = GUEST_LANGUAGE_COLUMN_NAME)
	int guestLangKey;
	@DBAnnotatedField(column = GUEST_SPACE_COLUMN_NAME)
	private int guestSpace;
	@DBAnnotatedField(column = GUEST_OFFSET_COLUMN_NAME)
	private long guestOffset;
	@DBAnnotatedField(column = LENGTH_COLUMN_NAME)
	private long length;

	private DBTraceLanguageManager manager;

	private AddressRangeImpl hostRange;
	private Language guestLanguage;
	private AddressRangeImpl guestRange;

	public DBTraceGuestLanguageMappedRange(DBTraceLanguageManager manager, DBCachedObjectStore<?> s,
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
		try {
			Address hostStart =
				manager.getBaseLanguage().getAddressFactory().getAddress(hostSpace, hostOffset);
			Address hostEnd = hostStart.addNoWrap(length - 1);
			this.hostRange = new AddressRangeImpl(hostStart, hostEnd);

			this.guestLanguage = manager.getLanguageByKey(guestLangKey);
			Address guestStart =
				guestLanguage.getAddressFactory().getAddress(guestSpace, guestOffset);
			Address guestEnd = guestStart.addNoWrap(length - 1);
			this.guestRange = new AddressRangeImpl(guestStart, guestEnd);
		}
		catch (AddressOverflowException e) {
			throw new RuntimeException("Database is corrupt or languages changed", e);
		}
	}

	void set(Address hostStart, Language guestLanguage, Address guestStart, long length) {
		this.hostRange = new AddressRangeImpl(hostStart, hostStart.add(length - 1));
		this.guestLanguage = guestLanguage;
		this.guestRange = new AddressRangeImpl(guestStart, guestStart.add(length - 1));

		this.hostSpace = hostStart.getAddressSpace().getSpaceID();
		this.hostOffset = hostStart.getOffset();
		this.guestLangKey = manager.getKeyForLanguage(guestLanguage);
		this.guestSpace = guestStart.getAddressSpace().getSpaceID();
		this.guestOffset = guestStart.getOffset();
		this.length = length;
		update(HOST_SPACE_COLUMN, HOST_OFFSET_COLUMN, GUEST_LANGUAGE_COLUMN, GUEST_SPACE_COLUMN,
			GUEST_OFFSET_COLUMN, LENGTH_COLUMN);
	}

	@Override
	public Language getHostLanguage() {
		return manager.getBaseLanguage();
	}

	@Override
	public AddressRange getHostRange() {
		return hostRange;
	}

	@Override
	public Language getGuestLanguage() {
		return guestLanguage;
	}

	@Override
	public AddressRange getGuestRange() {
		return guestRange;
	}

	@Override
	public Address mapHostToGuest(Address hostAddress) {
		if (!hostRange.contains(hostAddress)) {
			return null;
		}
		long offset = hostAddress.subtract(hostRange.getMinAddress());
		return guestRange.getMinAddress().add(offset);
	}

	@Override
	public Address mapGuestToHost(Address guestAddress) {
		if (!guestRange.contains(guestAddress)) {
			return null;
		}
		long offset = guestAddress.subtract(guestRange.getMinAddress());
		return hostRange.getMinAddress().add(offset);
	}

	@Override
	public void delete(TaskMonitor monitor) throws CancelledException {
		manager.languageStore.getObjectAt(guestLangKey).deleteMappedRange(this, monitor);
	}
}
