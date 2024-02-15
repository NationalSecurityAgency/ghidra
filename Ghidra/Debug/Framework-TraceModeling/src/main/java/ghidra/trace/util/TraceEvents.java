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

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.trace.model.Trace;
import ghidra.trace.model.bookmark.TraceBookmark;
import ghidra.trace.model.bookmark.TraceBookmarkType;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TraceGuestPlatformMappedRange;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.symbol.TraceSymbol;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.util.TraceEvent.*;

public interface TraceEvents {
	/**
	 * A {@link TraceObject} was created, but not yet inserted.
	 * 
	 * <p>
	 * Between the {@link #OBJECT_CREATED} event and the first {@link #OBJECT_LIFE_CHANGED} event,
	 * an object is considered "incomplete," because it is likely missing its attributes. Thus, a
	 * trace client must take care to ensure all attributes, especially fixed attributes, are added
	 * to the object before it is inserted at its canonical path. Listeners may use
	 * {@link TraceObject#getCanonicalParent(long)} to check if an object is complete for a given
	 * snapshot.
	 */
	TraceObjectEvent OBJECT_CREATED = TraceObjectEvent.OBJECT_CREATED;
	/**
	 * An object's life changed.
	 * 
	 * <p>
	 * One of its canonical parents was created, deleted, or had its lifespan change.
	 */
	TraceObjectEvent OBJECT_LIFE_CHANGED = TraceObjectEvent.OBJECT_LIFE_CHANGED;
	/** A {@link TraceObject} was deleted */
	TraceObjectEvent OBJECT_DELETED = TraceObjectEvent.OBJECT_DELETED;

	/** A {@link TraceObjectValue} was created */
	TraceObjectValueEvent VALUE_CREATED = TraceObjectValueEvent.VALUE_CREATED;
	/** A {@link TraceObjectValue}'s lifespan changed */
	TraceObjectValueLifespanEvent VALUE_LIFESPAN_CHANGED =
		TraceObjectValueLifespanEvent.VALUE_LIFESPAN_CHANGED;
	/** A {@link TraceObjectValue} was deleted */
	TraceObjectValueEvent VALUE_DELETED = TraceObjectValueEvent.VALUE_DELETED;

	/** A {@link TraceBookmarkType} was added */
	TraceBookmarkTypeEvent BOOKMARK_TYPE_ADDED = TraceBookmarkTypeEvent.BOOKMARK_TYPE_ADDED;
	/** A {@link TraceBookmark} was added */
	TraceBookmarkEvent BOOKMARK_ADDED = TraceBookmarkEvent.BOOKMARK_ADDED;
	/** A {@link TraceBookmark} was changed */
	TraceBookmarkEvent BOOKMARK_CHANGED = TraceBookmarkEvent.BOOKMARK_CHANGED;
	/** A {@link TraceBookmark}'s lifespan was changed */
	TraceBookmarkLifespanEvent BOOKMARK_LIFESPAN_CHANGED =
		TraceBookmarkLifespanEvent.BOOKMARK_LIFESPAN_CHANGED;
	/** A {@link TraceBookmark} was deleted */
	TraceBookmarkEvent BOOKMARK_DELETED = TraceBookmarkEvent.BOOKMARK_DELETED;

	/** A {@link TraceBreakpoint} was added */
	TraceBreakpointEvent BREAKPOINT_ADDED = TraceBreakpointEvent.BREAKPOINT_ADDED;
	/** A {@link TraceBreakpoint} was changed */
	TraceBreakpointEvent BREAKPOINT_CHANGED = TraceBreakpointEvent.BREAKPOINT_CHANGED;
	/** A {@link TraceBreakpoint}'s lifespan was changed */
	TraceBreakpointLifespanEvent BREAKPOINT_LIFESPAN_CHANGED =
		TraceBreakpointLifespanEvent.BREAKPOINT_LIFESPAN_CHANGED;
	/** A {@link TraceBreakpoint} was deleted */
	TraceBreakpointEvent BREAKPOINT_DELETED = TraceBreakpointEvent.BREAKPOINT_DELETED;

	/** A {@link Category} was added. The {@code long} is the category id. */
	TraceTypeCategoryEvent TYPE_CATEGORY_ADDED = TraceTypeCategoryEvent.TYPE_CATEGORY_ADDED;
	/** A {@link Category} was moved. The {@code long} is the category id. */
	TraceTypeCategoryPathEvent TYPE_CATEGORY_MOVED = TraceTypeCategoryPathEvent.TYPE_CATEGORY_MOVED;
	/** A {@link Category} was renamed. The {@code long} is the category id. */
	TraceTypeCategoryStringEvent TYPE_CATEGORY_RENAMED =
		TraceTypeCategoryStringEvent.TYPE_CATEGORY_RENAMED;
	/** A {@link Category} was deleted. The {@code long} is the category id. */
	TraceTypeCategoryPathEvent TYPE_CATEGORY_DELETED =
		TraceTypeCategoryPathEvent.TYPE_CATEGORY_DELETED;

	/**
	 * One or more {@link TraceCodeUnit}s were added.
	 * 
	 * <p>
	 * This may be a single unit or a whole block. Only the first unit in the block is given in the
	 * record.
	 */
	TraceCodeEvent CODE_ADDED = TraceCodeEvent.CODE_ADDED;
	/** A {@link TraceCodeUnit}'s lifspan changed. */
	TraceCodeLifespanEvent CODE_LIFESPAN_CHANGED = TraceCodeLifespanEvent.CODE_LIFESPAN_CHANGED;
	/**
	 * One or more {@link TraceCodeUnit}'s were removed.
	 * 
	 * <p>
	 * This may be a single unit or a whole block. Only the first unit in the block is given, if it
	 * is given at all.
	 */
	TraceCodeEvent CODE_REMOVED = TraceCodeEvent.CODE_REMOVED;
	/** A {@link ProgramFragment} was changed. */
	TraceCodeFragmentEvent CODE_FRAGMENT_CHANGED = TraceCodeFragmentEvent.CODE_FRAGMENT_CHANGED;
	/**
	 * One or more {@link TraceData}s' {@link DataType} was replaced.
	 * 
	 * <p>
	 * The type's id is given in the record.
	 */
	TraceCodeDataTypeEvent CODE_DATA_TYPE_REPLACED = TraceCodeDataTypeEvent.CODE_DATA_TYPE_REPLACED;
	/** One or more {@link TraceData}s' {@link Settings} was changed. */
	TraceCodeDataSettingsEvent CODE_DATA_SETTINGS_CHANGED =
		TraceCodeDataSettingsEvent.CODE_DATA_SETTINGS_CHANGED;

	/** A plate comment was changed. */
	TraceCommentEvent PLATE_COMMENT_CHANGED = TraceCommentEvent.PLATE_COMMENT_CHANGED;
	/** A pre comment was changed. */
	TraceCommentEvent PRE_COMMENT_CHANGED = TraceCommentEvent.PRE_COMMENT_CHANGED;
	/** A post comment was changed. */
	TraceCommentEvent POST_COMMENT_CHANGED = TraceCommentEvent.POST_COMMENT_CHANGED;
	/** An end-of-line comment was changed. */
	TraceCommentEvent EOL_COMMENT_CHANGED = TraceCommentEvent.EOL_COMMENT_CHANGED;
	/** A repeatable comment was changed. */
	TraceCommentEvent REPEATABLE_COMMENT_CHANGED = TraceCommentEvent.REPEATABLE_COMMENT_CHANGED;

	/**
	 * Get the comment change event for the given comment type
	 * 
	 * @param commentType the comment type
	 * @return the event type
	 */
	static TraceCommentEvent byCommentType(int commentType) {
		return switch (commentType) {
			case CodeUnit.PLATE_COMMENT -> PLATE_COMMENT_CHANGED;
			case CodeUnit.PRE_COMMENT -> PRE_COMMENT_CHANGED;
			case CodeUnit.POST_COMMENT -> POST_COMMENT_CHANGED;
			case CodeUnit.EOL_COMMENT -> EOL_COMMENT_CHANGED;
			case CodeUnit.REPEATABLE_COMMENT -> REPEATABLE_COMMENT_CHANGED;
			default -> throw new AssertionError();
		};
	}

	/** A {@link TraceData} of {@link Composite} type was added. */
	TraceCompositeDataEvent COMPOSITE_DATA_ADDED = TraceCompositeDataEvent.COMPOSITE_DATA_ADDED;
	/** The lifespan of a {@link TraceData} of {@link Composite} type was changed. */
	TraceCompositeDataLifespanEvent COMPOSITE_DATA_LIFESPAN_CHANGED =
		TraceCompositeDataLifespanEvent.COMPOSITE_DATA_LIFESPAN_CHANGED;
	/** A {@link TraceData} of {@link Composite} type was removed. */
	TraceCompositeDataEvent COMPOSITE_DATA_REMOVED = TraceCompositeDataEvent.COMPOSITE_DATA_REMOVED;

	/** A {@link DataType} was added. */
	TraceDataTypeEvent DATA_TYPE_ADDED = TraceDataTypeEvent.DATA_TYPE_ADDED;
	/** A {@link DataType} was replaced. */
	TraceDataTypePathEvent DATA_TYPE_REPLACED = TraceDataTypePathEvent.DATA_TYPE_REPLACED;
	/** A {@link DataType} was changed. */
	TraceDataTypeEvent DATA_TYPE_CHANGED = TraceDataTypeEvent.DATA_TYPE_CHANGED;
	/** A {@link DataType} was moved. */
	TraceDataTypePathEvent DATA_TYPE_MOVED = TraceDataTypePathEvent.DATA_TYPE_MOVED;
	/** A {@link DataType} was renamed. */
	TraceDataTypeStringEvent DATA_TYPE_RENAMED = TraceDataTypeStringEvent.DATA_TYPE_RENAMED;
	/** A {@link DataType} was deleted. */
	TraceDataTypePathEvent DATA_TYPE_DELETED = TraceDataTypePathEvent.DATA_TYPE_DELETED;

	/** A {@link TraceInstruction}'s flow override was changed. */
	TraceInstructionFlowEvent INSTRUCTION_FLOW_OVERRIDE_CHANGED =
		TraceInstructionFlowEvent.INSTRUCTION_FLOW_OVERRIDE_CHANGED;
	/** A {@link TraceInstruction}'s fall-through override was changed. */
	TraceInstructionBoolEvent INSTRUCTION_FALL_THROUGH_OVERRIDE_CHANGED =
		TraceInstructionBoolEvent.INSTRUCTION_FALL_THROUGH_OVERRIDE_CHANGED;
	/** A {@link TraceInstruction}'s length override was changed. */
	TraceInstructionIntEvent INSTRUCTION_LENGTH_OVERRIDE_CHANGED =
		TraceInstructionIntEvent.INSTRUCTION_LENGTH_OVERRIDE_CHANGED;

	/**
	 * The {@link Trace}'s memory or register values were changed.
	 * 
	 * <p>
	 * Note the given byte arrays may be larger than the actual change.
	 */
	TraceBytesEvent BYTES_CHANGED = TraceBytesEvent.BYTES_CHANGED;

	/** A {@link TraceMemoryRegion} was added. */
	TraceMemoryRegionEvent REGION_ADDED = TraceMemoryRegionEvent.REGION_ADDED;
	/** A {@link TraceMemoryRegion} was changed. */
	TraceMemoryRegionEvent REGION_CHANGED = TraceMemoryRegionEvent.REGION_CHANGED;
	/** A {@link TraceMemoryRegion}'s lifespan was changed. */
	TraceMemoryRegionLifespanEvent REGION_LIFESPAN_CHANGED =
		TraceMemoryRegionLifespanEvent.REGION_LIFESPAN_CHANGED;
	/** A {@link TraceMemoryRegion} was deleted. */
	TraceMemoryRegionEvent REGION_DELETED = TraceMemoryRegionEvent.REGION_DELETED;

	/** An overlay {@link AddressSpace} was added. */
	TraceOverlaySpaceEvent OVERLAY_ADDED = TraceOverlaySpaceEvent.OVERLAY_ADDED;
	/** An overlay {@link AddressSpace} was deleted. */
	TraceOverlaySpaceEvent OVERLAY_DELETED = TraceOverlaySpaceEvent.OVERLAY_DELETED;

	/** The cache state of memory or register values was changed. */
	TraceMemoryStateEvent BYTES_STATE_CHANGED = TraceMemoryStateEvent.BYTES_STATE_CHANGED;

	/** A {@link TraceModule} was added. */
	TraceModuleEvent MODULE_ADDED = TraceModuleEvent.MODULE_ADDED;
	/** A {@link TraceModule} was changed. */
	TraceModuleEvent MODULE_CHANGED = TraceModuleEvent.MODULE_CHANGED;
	/** A {@link TraceModule}'s lifespan was changed. */
	TraceModuleLifespanEvent MODULE_LIFESPAN_CHANGED =
		TraceModuleLifespanEvent.MODULE_LIFESPAN_CHANGED;
	/** A {@link TraceModule} was deleted. */
	TraceModuleEvent MODULE_DELETED = TraceModuleEvent.MODULE_DELETED;

	/** A {@link TraceSection} was added. */
	TraceSectionEvent SECTION_ADDED = TraceSectionEvent.SECTION_ADDED;
	/** A {@link TraceSection} was changed. */
	TraceSectionEvent SECTION_CHANGED = TraceSectionEvent.SECTION_CHANGED;
	/** A {@link TraceSection} was deleted. */
	TraceSectionEvent SECTION_DELETED = TraceSectionEvent.SECTION_DELETED;

	/** A {@link TraceReference} was added. */
	TraceReferenceEvent REFERENCE_ADDED = TraceReferenceEvent.REFERENCE_ADDED;
	/** A {@link TraceReference}'s lifespan was changed. */
	TraceReferenceLifespanEvent REFERENCE_LIFESPAN_CHANGED =
		TraceReferenceLifespanEvent.REFERENCE_LIFESPAN_CHANGED;
	/** A {@link TraceReference} was promoted to or demoted from primary. */
	TraceReferenceBoolEvent REFERENCE_PRIMARY_CHANGED =
		TraceReferenceBoolEvent.REFERENCE_PRIMARY_CHANGED;
	/** A {@link TraceReference} was deleted. */
	TraceReferenceEvent REFERENCE_DELETED = TraceReferenceEvent.REFERENCE_DELETED;

	/** A {@link TraceStack} was added. */
	TraceStackEvent STACK_ADDED = TraceStackEvent.STACK_ADDED;
	/**
	 * A {@link TraceStack} was changed.
	 * 
	 * <p>
	 * The "new value" in the record is the min snap of the change. The "old value" is always 0.
	 */
	TraceStackLongEvent STACK_CHANGED = TraceStackLongEvent.STACK_CHANGED;
	/** A {@link TraceStack} was deleted. */
	TraceStackEvent STACK_DELETED = TraceStackEvent.STACK_DELETED;

	/** A {@link TraceStaticMapping} was added. */
	TraceMappingEvent MAPPING_ADDED = TraceMappingEvent.MAPPING_ADDED;
	/** A {@link TraceStaticMapping} was deleted. */
	TraceMappingEvent MAPPING_DELETED = TraceMappingEvent.MAPPING_DELETED;

	/** A source data type archive was added. */
	TraceTypeArchiveEvent SOURCE_TYPE_ARCHIVE_ADDED =
		TraceTypeArchiveEvent.SOURCE_TYPE_ARCHIVE_ADDED;
	/** A source data type archive was changed. */
	TraceTypeArchiveEvent SOURCE_TYPE_ARCHIVE_CHANGED =
		TraceTypeArchiveEvent.SOURCE_TYPE_ARCHIVE_CHANGED;
	/** A source data type archive was deleted. */
	TraceTypeArchiveEvent SOURCE_TYPE_ARCHIVE_DELETED =
		TraceTypeArchiveEvent.SOURCE_TYPE_ARCHIVE_DELETED;

	/** A {@link TraceSymbol} was added. */
	TraceSymbolEvent SYMBOL_ADDED = TraceSymbolEvent.SYMBOL_ADDED;
	/** A {@link TraceSymbol}'s source type changed. */
	TraceSymbolSourceEvent SYMBOL_SOURCE_CHANGED = TraceSymbolSourceEvent.SYMBOL_SOURCE_CHANGED;
	/** A {@link TraceSymbol} was promoted to or demoted from primary. */
	TraceSymbolSymEvent SYMBOL_PRIMARY_CHANGED = TraceSymbolSymEvent.SYMBOL_PRIMARY_CHANGED;
	/** A {@link TraceSymbol} was renamed. */
	TraceSymbolStringEvent SYMBOL_RENAMED = TraceSymbolStringEvent.SYMBOL_RENAMED;
	/** A {@link TraceSymbol}'s parent namespace changed. */
	TraceSymbolNamespaceEvent SYMBOL_PARENT_CHANGED =
		TraceSymbolNamespaceEvent.SYMBOL_PARENT_CHANGED;
	/** A {@link TraceSymbol} was associated with a {@link TraceReference}. */
	TraceSymbolRefEvent SYMBOL_ASSOCIATION_ADDED = TraceSymbolRefEvent.SYMBOL_ASSOCIATION_ADDED;
	/** A {@link TraceSymbol} was dissociated from a {@link TraceReference}. */
	TraceSymbolRefEvent SYMBOL_ASSOCIATION_REMOVED = TraceSymbolRefEvent.SYMBOL_ASSOCIATION_REMOVED;
	/** A {@link TraceSymbol}'s address changed. */
	TraceSymbolAddressEvent SYMBOL_ADDRESS_CHANGED = TraceSymbolAddressEvent.SYMBOL_ADDRESS_CHANGED;
	/** A {@link TraceSymbol}'s lifespan changed. */
	TraceSymbolLifespanEvent SYMBOL_LIFESPAN_CHANGED =
		TraceSymbolLifespanEvent.SYMBOL_LIFESPAN_CHANGED;
	/**
	 * A {@link TraceSymbol} was changed in a way not captured by the other {@code SYMBOL_} events.
	 */
	TraceSymbolEvent SYMBOL_CHANGED = TraceSymbolEvent.SYMBOL_CHANGED;
	/** A {@link TraceSymbol} was deleted. */
	TraceSymbolEvent SYMBOL_DELETED = TraceSymbolEvent.SYMBOL_DELETED;

	/** A {@link TraceThread} was added. */
	TraceThreadEvent THREAD_ADDED = TraceThreadEvent.THREAD_ADDED;
	/** A {@link TraceThread} was changed. */
	TraceThreadEvent THREAD_CHANGED = TraceThreadEvent.THREAD_CHANGED;
	/** A {@link TraceThread}'s lifespan was changed. */
	TraceThreadLifespanEvent THREAD_LIFESPAN_CHANGED =
		TraceThreadLifespanEvent.THREAD_LIFESPAN_CHANGED;
	/** A {@link TraceThread} was deleted. */
	TraceThreadEvent THREAD_DELETED = TraceThreadEvent.THREAD_DELETED;

	/** A {@link TraceSnapshot} was added. */
	TraceSnapshotEvent SNAPSHOT_ADDED = TraceSnapshotEvent.SNAPSHOT_ADDED;
	/** A {@link TraceSnapshot} was changed. */
	TraceSnapshotEvent SNAPSHOT_CHANGED = TraceSnapshotEvent.SNAPSHOT_CHANGED;
	/** A {@link TraceSnapshot} was deleted. */
	TraceSnapshotEvent SNAPSHOT_DELETED = TraceSnapshotEvent.SNAPSHOT_DELETED;

	/** A {@link TraceGuestPlatform} was added. */
	TracePlatformEvent PLATFORM_ADDED = TracePlatformEvent.PLATFORM_ADDED;
	/** A {@link TraceGuestPlatform} was deleted. */
	TracePlatformEvent PLATFORM_DELETED = TracePlatformEvent.PLATFORM_DELETED;
	/** A {@link TraceGuestPlatformMappedRange} was added. */
	TracePlatformMappingEvent PLATFORM_MAPPING_ADDED =
		TracePlatformMappingEvent.PLATFORM_MAPPING_ADDED;
	/** A {@link TraceGuestPlatformMappedRange} was deleted. */
	TracePlatformMappingEvent PLATFORM_MAPPING_DELETED =
		TracePlatformMappingEvent.PLATFORM_MAPPING_DELETED;

}
