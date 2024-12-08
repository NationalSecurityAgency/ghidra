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
package ghidra.trace.util;

import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.model.*;
import ghidra.trace.model.bookmark.TraceBookmark;
import ghidra.trace.model.bookmark.TraceBookmarkType;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TraceGuestPlatformMappedRange;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.symbol.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.util.TypedEventDispatcher.FullEventRecordHandler;
import ghidra.util.UniversalID;

/**
 * A sub-type for event specific to traces.
 * 
 * <p>
 * For the various defined events, see {@link TraceEvents}.
 * 
 * <p>
 * This interface introduces two type parameters, which are provided by each trace event enum. They
 * describe the type of the effected object, e.g., a thread, as well as the type of the changed
 * value, e.g., its lifespan. These are can be enforced by using {@link TraceChangeRecord}. Its
 * constructors will ensure that the affected object and values actually match the types for the
 * given trace event. Conversely, by using {@link TraceDomainObjectListener} and registering
 * handlers for each event type, it will ensure each handler method accepts arguments of the correct
 * types. See, e.g., {@link TypedEventDispatcher#listenFor(TraceEvent, FullEventRecordHandler)}.
 * 
 * @param <T> the type of the object changed
 * @param <U> the type of the value
 */
public interface TraceEvent<T, U> extends EventType {

	/**
	 * Cast a change record to one with object/affected value types for this event
	 * 
	 * @param rec the untyped record
	 * @return the typed record
	 */
	@SuppressWarnings("unchecked")
	default TraceChangeRecord<T, U> cast(DomainObjectChangeRecord rec) {
		return (TraceChangeRecord<T, U>) rec;
	}

	enum TraceObjectEvent implements TraceEvent<TraceObject, Void> {
		OBJECT_CREATED, OBJECT_LIFE_CHANGED, OBJECT_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceObjectValueEvent implements TraceEvent<TraceObjectValue, Void> {
		VALUE_CREATED, VALUE_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceObjectValueLifespanEvent implements TraceEvent<TraceObjectValue, Lifespan> {
		VALUE_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceBookmarkTypeEvent implements TraceEvent<TraceBookmarkType, Void> {
		BOOKMARK_TYPE_ADDED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceBookmarkEvent implements TraceEvent<TraceBookmark, Void> {
		BOOKMARK_ADDED, BOOKMARK_CHANGED, BOOKMARK_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceBookmarkLifespanEvent implements TraceEvent<TraceBookmark, Lifespan> {
		BOOKMARK_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceBreakpointEvent implements TraceEvent<TraceBreakpoint, Void> {
		BREAKPOINT_ADDED, BREAKPOINT_CHANGED, BREAKPOINT_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceBreakpointLifespanEvent implements TraceEvent<TraceBreakpoint, Lifespan> {
		BREAKPOINT_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceTypeCategoryEvent implements TraceEvent<Long, Category> {
		TYPE_CATEGORY_ADDED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceTypeCategoryPathEvent implements TraceEvent<Long, CategoryPath> {
		TYPE_CATEGORY_MOVED, TYPE_CATEGORY_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceTypeCategoryStringEvent implements TraceEvent<Long, String> {
		TYPE_CATEGORY_RENAMED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceCodeEvent implements TraceEvent<TraceAddressSnapRange, TraceCodeUnit> {
		CODE_ADDED, CODE_REMOVED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceCodeLifespanEvent implements TraceEvent<TraceCodeUnit, Lifespan> {
		CODE_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceCodeFragmentEvent implements TraceEvent<TraceAddressSnapRange, ProgramFragment> {
		CODE_FRAGMENT_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceCodeDataTypeEvent implements TraceEvent<TraceAddressSnapRange, Long> {
		CODE_DATA_TYPE_REPLACED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceCodeDataSettingsEvent implements TraceEvent<TraceAddressSnapRange, Void> {
		CODE_DATA_SETTINGS_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceCommentEvent implements TraceEvent<TraceAddressSnapRange, String> {
		PLATE_COMMENT_CHANGED,
		PRE_COMMENT_CHANGED,
		POST_COMMENT_CHANGED,
		EOL_COMMENT_CHANGED,
		REPEATABLE_COMMENT_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceCompositeDataEvent implements TraceEvent<TraceAddressSnapRange, TraceData> {
		COMPOSITE_DATA_ADDED, COMPOSITE_DATA_REMOVED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceCompositeDataLifespanEvent implements TraceEvent<TraceData, Lifespan> {
		COMPOSITE_DATA_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceDataTypeEvent implements TraceEvent<Long, DataType> {
		DATA_TYPE_ADDED, DATA_TYPE_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceDataTypePathEvent implements TraceEvent<Long, DataTypePath> {
		DATA_TYPE_REPLACED, DATA_TYPE_MOVED, DATA_TYPE_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceDataTypeStringEvent implements TraceEvent<Long, String> {
		DATA_TYPE_RENAMED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceInstructionFlowEvent implements TraceEvent<TraceInstruction, FlowOverride> {
		INSTRUCTION_FLOW_OVERRIDE_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceInstructionBoolEvent implements TraceEvent<TraceInstruction, Boolean> {
		INSTRUCTION_FALL_THROUGH_OVERRIDE_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceInstructionIntEvent implements TraceEvent<TraceInstruction, Integer> {
		INSTRUCTION_LENGTH_OVERRIDE_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceBytesEvent implements TraceEvent<TraceAddressSnapRange, byte[]> {
		BYTES_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceMemoryRegionEvent implements TraceEvent<TraceMemoryRegion, Void> {
		REGION_ADDED, REGION_CHANGED, REGION_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceMemoryRegionLifespanEvent implements TraceEvent<TraceMemoryRegion, Lifespan> {
		REGION_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceOverlaySpaceEvent implements TraceEvent<Trace, AddressSpace> {
		OVERLAY_ADDED, OVERLAY_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceMemoryStateEvent implements TraceEvent<TraceAddressSnapRange, TraceMemoryState> {
		BYTES_STATE_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceModuleEvent implements TraceEvent<TraceModule, Void> {
		MODULE_ADDED, MODULE_CHANGED, MODULE_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceModuleLifespanEvent implements TraceEvent<TraceModule, Lifespan> {
		MODULE_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSectionEvent implements TraceEvent<TraceSection, Void> {
		SECTION_ADDED, SECTION_CHANGED, SECTION_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceReferenceEvent implements TraceEvent<TraceAddressSnapRange, TraceReference> {
		REFERENCE_ADDED, REFERENCE_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceReferenceLifespanEvent implements TraceEvent<TraceReference, Lifespan> {
		REFERENCE_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceReferenceBoolEvent implements TraceEvent<TraceReference, Boolean> {
		REFERENCE_PRIMARY_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceStackEvent implements TraceEvent<TraceStack, Void> {
		STACK_ADDED, STACK_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceStackLongEvent implements TraceEvent<TraceStack, Long> {
		STACK_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceMappingEvent implements TraceEvent<TraceStaticMapping, Void> {
		MAPPING_ADDED, MAPPING_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceTypeArchiveEvent implements TraceEvent<UniversalID, Void> {
		SOURCE_TYPE_ARCHIVE_ADDED, SOURCE_TYPE_ARCHIVE_CHANGED, SOURCE_TYPE_ARCHIVE_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSymbolEvent implements TraceEvent<TraceSymbol, Void> {
		SYMBOL_ADDED, SYMBOL_CHANGED, SYMBOL_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSymbolSourceEvent implements TraceEvent<TraceSymbol, SourceType> {
		SYMBOL_SOURCE_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSymbolSymEvent implements TraceEvent<TraceSymbol, TraceSymbol> {
		SYMBOL_PRIMARY_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSymbolStringEvent implements TraceEvent<TraceSymbol, String> {
		SYMBOL_RENAMED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSymbolNamespaceEvent implements TraceEvent<TraceSymbol, TraceNamespaceSymbol> {
		SYMBOL_PARENT_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSymbolRefEvent implements TraceEvent<TraceSymbol, TraceReference> {
		SYMBOL_ASSOCIATION_ADDED, SYMBOL_ASSOCIATION_REMOVED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSymbolAddressEvent implements TraceEvent<TraceSymbol, Address> {
		SYMBOL_ADDRESS_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSymbolLifespanEvent implements TraceEvent<TraceSymbolWithLifespan, Lifespan> {
		SYMBOL_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceThreadEvent implements TraceEvent<TraceThread, Void> {
		THREAD_ADDED, THREAD_CHANGED, THREAD_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceThreadLifespanEvent implements TraceEvent<TraceThread, Lifespan> {
		THREAD_LIFESPAN_CHANGED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TraceSnapshotEvent implements TraceEvent<TraceSnapshot, Void> {
		SNAPSHOT_ADDED, SNAPSHOT_CHANGED, SNAPSHOT_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TracePlatformEvent implements TraceEvent<TraceGuestPlatform, Void> {
		PLATFORM_ADDED, PLATFORM_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}

	enum TracePlatformMappingEvent
		implements TraceEvent<TraceGuestPlatform, TraceGuestPlatformMappedRange> {
		PLATFORM_MAPPING_ADDED, PLATFORM_MAPPING_DELETED;

		private final int id = DomainObjectEventIdGenerator.next();

		@Override
		public int getId() {
			return id;
		}
	}
}
