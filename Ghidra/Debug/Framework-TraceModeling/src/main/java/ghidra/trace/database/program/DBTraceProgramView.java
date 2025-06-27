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
package ghidra.trace.database.program;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.BiFunction;

import org.apache.commons.lang3.tuple.Pair;

import db.Transaction;
import ghidra.framework.data.DomainObjectEventQueues;
import ghidra.framework.data.DomainObjectFileListener;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.IntRangeMap;
import ghidra.program.database.ProgramOverlayAddressSpace;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.util.*;
import ghidra.trace.database.*;
import ghidra.trace.database.guest.InternalTracePlatform;
import ghidra.trace.database.listing.DBTraceCodeSpace;
import ghidra.trace.database.listing.DBTraceDefinedUnitsView;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.*;
import ghidra.trace.model.TraceTimeViewport.Occlusion;
import ghidra.trace.model.TraceTimeViewport.RangeQueryOcclusion;
import ghidra.trace.model.bookmark.TraceBookmark;
import ghidra.trace.model.bookmark.TraceBookmarkType;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.symbol.*;
import ghidra.trace.util.TraceEvents;
import ghidra.trace.util.TypedEventDispatcher;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * A wrapper on a trace, which given a snap, implements the {@link Program} interface
 * 
 * <p>
 * NOTE: Calling {@link CodeUnit#getProgram()} from units contained in this view may not necessarily
 * return this same view. If the code unit comes from a less-recent snap than the snap associated
 * with this view, the view for that snap is returned instead.
 * 
 * <p>
 * TODO: Unit tests for all of this.
 */
public class DBTraceProgramView implements TraceProgramView {
	public static final int TIME_INTERVAL = 100;
	public static final int BUF_SIZE = 1000;

	protected class EventTranslator extends TypedEventDispatcher
			implements DBTraceDirectChangeListener {
		public EventTranslator() {
			listenForUntyped(DomainObjectEvent.SAVED, this::eventPassthrough);
			listenForUntyped(DomainObjectEvent.FILE_CHANGED, this::eventPassthrough);
			listenForUntyped(DomainObjectEvent.RENAMED, this::eventPassthrough);
			listenForUntyped(DomainObjectEvent.RESTORED, this::objectRestored);
			listenForUntyped(DomainObjectEvent.CLOSED, this::eventPassthrough);
			listenForUntyped(DomainObjectEvent.ERROR, this::eventPassthrough);

			listenFor(TraceEvents.BOOKMARK_TYPE_ADDED, this::bookmarkTypeAdded);
			listenFor(TraceEvents.BOOKMARK_ADDED, this::bookmarkAdded);
			listenFor(TraceEvents.BOOKMARK_CHANGED, this::bookmarkChanged);
			listenFor(TraceEvents.BOOKMARK_LIFESPAN_CHANGED, this::bookmarkLifespanChanged);
			listenFor(TraceEvents.BOOKMARK_DELETED, this::bookmarkDeleted);

			listenFor(TraceEvents.TYPE_CATEGORY_ADDED, this::categoryAdded);
			listenFor(TraceEvents.TYPE_CATEGORY_MOVED, this::categoryMoved);
			listenFor(TraceEvents.TYPE_CATEGORY_RENAMED, this::categoryRenamed);
			listenFor(TraceEvents.TYPE_CATEGORY_DELETED, this::categoryDeleted);

			listenFor(TraceEvents.CODE_ADDED, this::codeAdded);
			listenFor(TraceEvents.CODE_LIFESPAN_CHANGED, this::codeLifespanChanged);
			listenFor(TraceEvents.CODE_REMOVED, this::codeRemoved);
			listenFor(TraceEvents.CODE_FRAGMENT_CHANGED, this::codeFragmentChanged);
			listenFor(TraceEvents.CODE_DATA_TYPE_REPLACED, this::codeDataTypeReplaced);
			listenFor(TraceEvents.CODE_DATA_SETTINGS_CHANGED, this::codeDataTypeSettingsChanged);

			listenFor(TraceEvents.EOL_COMMENT_CHANGED, this::commentEolChanged);
			listenFor(TraceEvents.PLATE_COMMENT_CHANGED, this::commentPlateChanged);
			listenFor(TraceEvents.POST_COMMENT_CHANGED, this::commentPostChanged);
			listenFor(TraceEvents.PRE_COMMENT_CHANGED, this::commentPreChanged);
			listenFor(TraceEvents.REPEATABLE_COMMENT_CHANGED, this::commentRepeatableChanged);

			listenFor(TraceEvents.COMPOSITE_DATA_ADDED, this::compositeDataAdded);
			listenFor(TraceEvents.COMPOSITE_DATA_LIFESPAN_CHANGED, this::compositeLifespanChanged);
			listenFor(TraceEvents.COMPOSITE_DATA_REMOVED, this::compositeDataRemoved);

			listenFor(TraceEvents.DATA_TYPE_ADDED, this::dataTypeAdded);
			listenFor(TraceEvents.DATA_TYPE_CHANGED, this::dataTypeChanged);
			listenFor(TraceEvents.DATA_TYPE_REPLACED, this::dataTypeReplaced);
			listenFor(TraceEvents.DATA_TYPE_MOVED, this::dataTypeMoved);
			listenFor(TraceEvents.DATA_TYPE_RENAMED, this::dataTypeRenamed);
			listenFor(TraceEvents.DATA_TYPE_DELETED, this::dataTypeDeleted);

			listenFor(TraceEvents.INSTRUCTION_LENGTH_OVERRIDE_CHANGED,
				this::instructionLengthOverrideChanged);
			listenFor(TraceEvents.INSTRUCTION_FLOW_OVERRIDE_CHANGED,
				this::instructionFlowOverrideChanged);
			listenFor(TraceEvents.INSTRUCTION_FALL_THROUGH_OVERRIDE_CHANGED,
				this::instructionFallThroughChanged);

			listenFor(TraceEvents.BYTES_CHANGED, this::memoryBytesChanged);

			listenFor(TraceEvents.REGION_ADDED, this::memoryRegionAdded);
			listenFor(TraceEvents.REGION_CHANGED, this::memoryRegionChanged);
			listenFor(TraceEvents.REGION_LIFESPAN_CHANGED, this::memoryRegionLifespanChanged);
			listenFor(TraceEvents.REGION_DELETED, this::memoryRegionDeleted);

			listenFor(TraceEvents.SOURCE_TYPE_ARCHIVE_ADDED, this::sourceArchiveAdded);
			listenFor(TraceEvents.SOURCE_TYPE_ARCHIVE_CHANGED, this::sourceArchiveChanged);

			listenFor(TraceEvents.SYMBOL_ADDED, this::symbolAdded);
			listenFor(TraceEvents.SYMBOL_SOURCE_CHANGED, this::symbolSourceChanged);
			listenFor(TraceEvents.SYMBOL_PRIMARY_CHANGED, this::symbolSetAsPrimary);
			listenFor(TraceEvents.SYMBOL_RENAMED, this::symbolRenamed);
			listenFor(TraceEvents.SYMBOL_PARENT_CHANGED, this::symbolParentChanged);
			listenFor(TraceEvents.SYMBOL_ASSOCIATION_ADDED, this::symbolAssociationAdded);
			listenFor(TraceEvents.SYMBOL_ASSOCIATION_REMOVED, this::symbolAssociationRemoved);
			listenFor(TraceEvents.SYMBOL_ADDRESS_CHANGED, this::symbolAddressChanged);
			listenFor(TraceEvents.SYMBOL_LIFESPAN_CHANGED, this::symbolLifespanChanged);
			listenFor(TraceEvents.SYMBOL_DELETED, this::symbolDeleted);
		}

		@Override
		public void changed(DomainObjectChangeRecord event) {
			handleChangeRecord(event);
		}

		private void eventPassthrough(DomainObjectChangeRecord rec) {
			fireEventAllViews(rec);
		}

		private void objectRestored(DomainObjectChangeRecord rec) {
			versionTag++;
			fireEventAllViews(rec);
		}

		private void bookmarkTypeAdded(TraceBookmarkType type) {
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.BOOKMARK_TYPE_ADDED, null, null,
				type, null, null));
		}

		private void bookmarkAdded(AddressSpace space, TraceBookmark bm) {
			DomainObjectEventQueues queues = isBookmarkVisible(space, bm);
			if (queues == null) {
				return;
			}
			fireBookmarkAdded(queues, bm);
		}

		protected void fireBookmarkAdded(DomainObjectEventQueues queues, TraceBookmark bm) {
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.BOOKMARK_ADDED, bm.getAddress(),
				bm.getAddress(), bm, null, null));
		}

		private void bookmarkChanged(AddressSpace space, TraceBookmark bm) {
			DomainObjectEventQueues queues = isBookmarkVisible(space, bm);
			if (queues == null) {
				return;
			}
			fireBookmarkChanged(queues, bm);
		}

		protected void fireBookmarkChanged(DomainObjectEventQueues queues, TraceBookmark bm) {
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.BOOKMARK_CHANGED, bm.getAddress(),
				bm.getAddress(), bm, null, null));
		}

		private void bookmarkLifespanChanged(AddressSpace space, TraceBookmark bm, Lifespan oldSpan,
				Lifespan newSpan) {
			DomainObjectEventQueues queues = getEventQueues(space);
			if (queues == null) {
				return;
			}
			boolean inOld = isBookmarkVisible(bm, oldSpan);
			boolean inNew = isBookmarkVisible(bm, newSpan);
			if (inOld && !inNew) {
				fireBookmarkRemoved(queues, bm);
			}
			if (!inOld && inNew) {
				fireBookmarkAdded(queues, bm);
			}
		}

		private void bookmarkDeleted(AddressSpace space, TraceBookmark bm) {
			DomainObjectEventQueues queues = isBookmarkVisible(space, bm);
			if (queues == null) {
				return;
			}
			fireBookmarkRemoved(queues, bm);
		}

		protected void fireBookmarkRemoved(DomainObjectEventQueues queues, TraceBookmark bm) {
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.BOOKMARK_REMOVED, bm.getAddress(),
				bm.getAddress(), bm, null, null));
		}

		private void categoryAdded(long id, Category oldIsNull, Category added) {
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_CATEGORY_ADDED, null,
				null, null, oldIsNull, added));
		}

		private void categoryMoved(long id, CategoryPath oldPath, CategoryPath newPath) {
			Category category = getDataTypeManager().getCategory(id);
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_CATEGORY_MOVED, null,
				null, null, oldPath, category));
		}

		private void categoryRenamed(long id, String oldName, String newName) {
			Category category = getDataTypeManager().getCategory(id);
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_CATEGORY_RENAMED, null,
				null, null, oldName, category));
		}

		private void categoryDeleted(long id, CategoryPath deleted, CategoryPath newIsNull) {
			Category parent = getDataTypeManager().getCategory(deleted.getParent());
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_CATEGORY_REMOVED, null,
				null, null, parent, deleted.getName()));
		}

		private void codeAdded(AddressSpace space, TraceAddressSnapRange range,
				TraceCodeUnit oldIsNull, TraceCodeUnit added) {
			// NOTE: Added code may be coalesced range. -added- is just first unit.
			// TODO: The range may contain many units, so this could be broken down
			DomainObjectEventQueues queues =
				isCodeVisible(space, range) ? getEventQueues(space) : null;
			if (queues == null) {
				return;
			}
			fireCodeAdded(queues, range.getX1(), range.getX2());
		}

		protected void fireCodeAdded(DomainObjectEventQueues queues, Address min, Address max) {
			queues.fireEvent(
				new ProgramChangeRecord(ProgramEvent.CODE_ADDED, min, max, null, null, null));
		}

		private void codeLifespanChanged(AddressSpace space, TraceCodeUnit unit, Lifespan oldSpan,
				Lifespan newSpan) {
			DomainObjectEventQueues queues = getEventQueues(space);
			if (queues == null) {
				return;
			}
			boolean inOld = isCodeVisible(unit, oldSpan);
			boolean inNew = isCodeVisible(unit, newSpan);
			if (inOld && !inNew) {
				fireCodeRemoved(queues, unit.getMinAddress(), unit.getMaxAddress(), unit);
			}
			if (!inOld && inNew) {
				fireCodeAdded(queues, unit.getMinAddress(), unit.getMaxAddress());
			}
		}

		private void codeRemoved(AddressSpace space, TraceAddressSnapRange range,
				TraceCodeUnit removed, TraceCodeUnit newIsNull) {
			// NOTE: Removed code may be coalesced range. -removed- is just first unit.
			DomainObjectEventQueues queues = isCodeVisible(space, removed);
			if (queues == null) {
				return;
			}
			fireCodeRemoved(queues, range.getX1(), range.getX2(), removed);
		}

		protected void fireCodeRemoved(DomainObjectEventQueues queues, Address min, Address max,
				TraceCodeUnit removed) {
			queues.fireEvent(
				new ProgramChangeRecord(ProgramEvent.CODE_REMOVED, min, max, null, removed, null));
		}

		private void codeFragmentChanged(AddressSpace space, TraceAddressSnapRange range,
				ProgramFragment oldFragment, ProgramFragment newFragment) {
			DomainObjectEventQueues queues = isVisible(space, range);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.FRAGMENT_CHANGED, null, null,
				null, range.getX1(), range.getX2()));
		}

		private void codeDataTypeReplaced(AddressSpace space, TraceAddressSnapRange range,
				Long oldDataTypeID, Long newDataTypeID) {
			// TODO??: "code" visibility check may not be necessary or advantageous
			DomainObjectEventQueues queues = isVisible(space, range);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_REPLACED, range.getX1(),
				range.getX2(), null, null, null));
		}

		private void codeDataTypeSettingsChanged(AddressSpace space,
				TraceAddressSnapRange range) {
			DomainObjectEventQueues queues = isVisible(space, range);
			if (queues == null) {
				return;
			}
			// Yes, x1 twice
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_SETTING_CHANGED,
				range.getX1(), range.getX1(), null, null, null));
		}

		private void commentChanged(CommentType commentType, AddressSpace space,
				TraceAddressSnapRange range, String oldValue, String newValue) {
			DomainObjectEventQueues queues = isVisible(space, range);
			if (queues == null) {
				return;
			}
			queues.fireEvent(
				new CommentChangeRecord(commentType, range.getX1(), oldValue, newValue));
		}

		private void commentEolChanged(AddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			commentChanged(CommentType.EOL, space, range, oldValue, newValue);
		}

		private void commentPlateChanged(AddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			commentChanged(CommentType.PLATE, space, range, oldValue, newValue);
		}

		private void commentPostChanged(AddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			commentChanged(CommentType.POST, space, range, oldValue, newValue);
		}

		private void commentPreChanged(AddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			commentChanged(CommentType.PRE, space, range, oldValue, newValue);
		}

		private void commentRepeatableChanged(AddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			// TODO: The "repeatable" semantics are not implemented, yet.
			commentChanged(CommentType.REPEATABLE, space, range, oldValue, newValue);
		}

		private void compositeDataAdded(AddressSpace space, TraceAddressSnapRange range,
				TraceData oldIsNull, TraceData added) {
			DomainObjectEventQueues queues = isCodeVisible(space, added);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.COMPOSITE_ADDED,
				added.getMinAddress(), added.getMaxAddress(), null, null, added));
		}

		private void compositeLifespanChanged(AddressSpace space, TraceData data, Lifespan oldSpan,
				Lifespan newSpan) {
			DomainObjectEventQueues queues = getEventQueues(space);
			if (queues == null) {
				return;
			}
			boolean inOld = isCodeVisible(data, oldSpan);
			boolean inNew = isCodeVisible(data, newSpan);
			if (inOld && !inNew) {
				queues.fireEvent(new ProgramChangeRecord(ProgramEvent.COMPOSITE_REMOVED,
					data.getMinAddress(), data.getMaxAddress(), null, data, null));
			}
			if (!inOld && inNew) {
				queues.fireEvent(new ProgramChangeRecord(ProgramEvent.COMPOSITE_ADDED,
					data.getMinAddress(), data.getMaxAddress(), null, null, data));
			}
		}

		private void compositeDataRemoved(AddressSpace space, TraceAddressSnapRange range,
				TraceData removed, TraceData newIsNull) {
			DomainObjectEventQueues queues = isCodeVisible(space, removed);
			if (queues == null) {
				return;
			}
			// TODO: ProgramDB doesn't send this.... Should I?
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.COMPOSITE_REMOVED,
				removed.getMinAddress(), removed.getMaxAddress(), null, removed, null));
		}

		private void dataTypeAdded(long id, DataType oldIsNull, DataType added) {
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_ADDED, null, null,
				null, oldIsNull, added));
		}

		private void dataTypeChanged(long id, DataType oldIsNull, DataType changed) {
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_CHANGED, null, null,
				null, oldIsNull, changed));
		}

		private void dataTypeReplaced(long id, DataTypePath oldPath, DataTypePath newPath) {
			DataType newType = getDataTypeManager().getDataType(id);
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_REPLACED, null, null,
				null, newPath, newType));
		}

		private void dataTypeMoved(long id, DataTypePath oldPath, DataTypePath newPath) {
			Category oldCategory = getDataTypeManager().getCategory(oldPath.getCategoryPath());
			DataType dataType = getDataTypeManager().getDataType(id);
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_MOVED, null, null,
				null, oldCategory, dataType));
		}

		private void dataTypeRenamed(long id, String oldName, String newName) {
			DataType dataType = getDataTypeManager().getDataType(id);
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_RENAMED, null, null,
				null, oldName, dataType));
		}

		private void dataTypeDeleted(long id, DataTypePath oldPath, DataTypePath newIsNull) {
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.DATA_TYPE_REMOVED, null, null,
				null, oldPath, newIsNull));
		}

		private void instructionFlowOverrideChanged(AddressSpace space,
				TraceInstruction instruction, FlowOverride oldOverride, FlowOverride newOverride) {
			DomainObjectEventQueues queues = isCodeVisible(space, instruction);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.FLOW_OVERRIDE_CHANGED,
				instruction.getMinAddress(), instruction.getMinAddress(), null, null, null));
		}

		private void instructionFallThroughChanged(AddressSpace space,
				TraceInstruction instruction, boolean oldFallThrough, boolean newFallThrough) {
			DomainObjectEventQueues queues = isCodeVisible(space, instruction);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.FALLTHROUGH_CHANGED,
				instruction.getMinAddress(), instruction.getMinAddress(), null, null, null));
		}

		private void instructionLengthOverrideChanged(AddressSpace space,
				TraceInstruction instruction, int oldLengthOverride, int newLengthOverride) {
			DomainObjectEventQueues queues = isCodeVisible(space, instruction);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.LENGTH_OVERRIDE_CHANGED,
				instruction.getMinAddress(), instruction.getMinAddress(), null, null, null));
		}

		private void memoryBytesChanged(AddressSpace space, TraceAddressSnapRange range,
				byte[] oldIsNull, byte[] bytes) {
			DomainObjectEventQueues queues = isBytesVisible(space, range);
			if (queues == null) {
				return;
			}
			fireMemoryBytesChanged(queues, range);
		}

		protected void fireMemoryBytesChanged(DomainObjectEventQueues queues,
				TraceAddressSnapRange range) {
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.MEMORY_BYTES_CHANGED,
				range.getX1(), range.getX2(), null, null, null));
		}

		private void memoryRegionAdded(AddressSpace space, TraceMemoryRegion region) {
			// This is handled via another path
		}

		private void memoryRegionChanged(AddressSpace space, TraceMemoryRegion region) {
			// Could be a name change, which must get communicated to program.
			// RESTORED may be duplicative, but should get de-duped by event manager.
			eventQueues.fireEvent(new DomainObjectChangeRecord(DomainObjectEvent.RESTORED));
		}

		private void memoryRegionLifespanChanged(AddressSpace space, TraceMemoryRegion region,
				Lifespan oldSpan, Lifespan newSpan) {
			// This is handled via another path
		}

		private void memoryRegionDeleted(AddressSpace space, TraceMemoryRegion region) {
			// HACK
			listing.fragmentsByRegion.remove(region);
			// END HACK

			// Memory stuff handled via another path
		}

		private void sourceArchiveAdded(UniversalID id) {
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.SOURCE_ARCHIVE_ADDED, null, null,
				id, null, null));
		}

		private void sourceArchiveChanged(UniversalID id) {
			fireEventAllViews(new ProgramChangeRecord(ProgramEvent.SOURCE_ARCHIVE_CHANGED, null,
				null, id, null, null));
		}

		private void symbolAdded(AddressSpace space, TraceSymbol symbol) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			fireSymbolAdded(queues, symbol);
		}

		public void fireSymbolAdded(DomainObjectEventQueues queues, TraceSymbol symbol) {
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.SYMBOL_ADDED, symbol.getAddress(),
				symbol.getAddress(), null, null, symbol));
		}

		private void symbolSourceChanged(AddressSpace space, TraceSymbol symbol) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.SYMBOL_SOURCE_CHANGED,
				symbol.getAddress(), symbol.getAddress(), symbol, null, null));
		}

		private void symbolSetAsPrimary(AddressSpace space, TraceSymbol symbol,
				TraceSymbol oldPrimary, TraceSymbol newPrimary) {
			// NOTE symbol == newPrimary
			DomainObjectEventQueues newQueues = isSymbolVisible(space, symbol);
			if (newQueues == null) {
				return;
			}
			DomainObjectEventQueues oldQueues = isSymbolVisible(space, oldPrimary);
			if (oldPrimary != null && oldQueues == null) {
				oldPrimary = null;
			}
			assert oldQueues == newQueues || oldQueues == null;
			newQueues.fireEvent(new ProgramChangeRecord(ProgramEvent.SYMBOL_PRIMARY_STATE_CHANGED,
				symbol.getAddress(), symbol.getAddress(), null, oldPrimary, newPrimary));
		}

		private void symbolRenamed(AddressSpace space, TraceSymbol symbol, String oldName,
				String newName) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.SYMBOL_RENAMED,
				symbol.getAddress(), symbol.getAddress(), symbol, oldName, newName));
		}

		private void symbolParentChanged(AddressSpace space, TraceSymbol symbol,
				TraceNamespaceSymbol oldParent, TraceNamespaceSymbol newParent) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.SYMBOL_SCOPE_CHANGED,
				symbol.getAddress(), symbol.getAddress(), symbol, oldParent, newParent));
		}

		private void symbolAssociationAdded(AddressSpace space, TraceSymbol symbol,
				TraceReference oldRefIsNull, TraceReference newRef) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			// Strange. This is fired as if by the reference rather than the symbol
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.SYMBOL_ASSOCIATION_ADDED,
				newRef.getFromAddress(), newRef.getFromAddress(), newRef, null, symbol));
		}

		private void symbolAssociationRemoved(AddressSpace space, TraceSymbol symbol,
				TraceReference oldRef, TraceReference newRefIsNull) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			// Ditto as ADDED
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.SYMBOL_ASSOCIATION_REMOVED,
				oldRef.getFromAddress(), oldRef.getFromAddress(), oldRef, symbol, null));
		}

		private void symbolAddressChanged(AddressSpace space, TraceSymbol symbol,
				Address oldAddress, Address newAddress) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ProgramEvent.SYMBOL_ADDRESS_CHANGED,
				oldAddress, oldAddress, symbol, oldAddress, newAddress));
		}

		private void symbolLifespanChanged(AddressSpace space, TraceSymbolWithLifespan symbol,
				Lifespan oldSpan, Lifespan newSpan) {
			DomainObjectEventQueues queues = getEventQueues(space);
			if (queues == null) {
				return;
			}
			boolean inOld = isSymbolWithLifespanVisible(symbol, oldSpan);
			boolean inNew = isSymbolWithLifespanVisible(symbol, newSpan);
			if (inOld && !inNew) {
				fireSymbolRemoved(queues, symbol);
			}
			if (!inOld && inNew) {
				fireSymbolAdded(queues, symbol);
			}
		}

		private void symbolDeleted(AddressSpace space, TraceSymbol symbol) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			fireSymbolRemoved(queues, symbol);
		}

		protected void fireSymbolRemoved(DomainObjectEventQueues queues, TraceSymbol symbol) {
			queues.fireEvent(
				new ProgramChangeRecord(ProgramEvent.SYMBOL_REMOVED, symbol.getAddress(),
					symbol.getAddress(), symbol, symbol.getName(), symbol.getID()));
		}
	}

	protected static class OverlappingAddressRangeKeyIteratorMerger<T> extends
			PairingIteratorMerger<Entry<AddressRange, T>, Entry<AddressRange, T>, Entry<AddressRange, T>> {

		protected static <T> Iterable<Pair<Entry<AddressRange, T>, Entry<AddressRange, T>>> iter(
				Iterable<Entry<AddressRange, T>> left, Iterable<Entry<AddressRange, T>> right) {
			return new Iterable<>() {
				@Override
				public Iterator<Pair<Entry<AddressRange, T>, Entry<AddressRange, T>>> iterator() {
					return new OverlappingAddressRangeKeyIteratorMerger<>(left.iterator(),
						right.iterator());
				}
			};
		}

		public OverlappingAddressRangeKeyIteratorMerger(Iterator<Entry<AddressRange, T>> left,
				Iterator<Entry<AddressRange, T>> right) {
			super(left, right);
		}

		@Override
		public int compare(Entry<AddressRange, T> o1, Entry<AddressRange, T> o2) {
			return o1.getKey().getMaxAddress().compareTo(o2.getKey().getMaxAddress());
		}

		@Override
		public boolean test(Entry<AddressRange, T> t, Entry<AddressRange, T> u) {
			return t.getKey().intersects(u.getKey());
		}
	}

	protected final DBTrace trace;
	protected final LanguageID languageID;
	protected final Language language;
	protected final CompilerSpec compilerSpec;

	protected final DomainObjectEventQueues eventQueues;
	protected EventTranslator eventTranslator;
	private volatile boolean allAddressesValid;
	private volatile AddressSetView allAddresses;

	protected final DBTraceProgramViewBookmarkManager bookmarkManager;
	protected final DBTraceProgramViewEquateTable equateTable;
	protected final DBTraceProgramViewFunctionManager functionManager;
	protected final DBTraceProgramViewListing listing;
	protected final DBTraceProgramViewMemory memory;
	protected final DBTraceProgramViewProgramContext programContext;
	protected final DBTraceProgramViewPropertyMapManager propertyMapManager;
	protected final DBTraceProgramViewReferenceManager referenceManager;
	protected final DBTraceProgramViewSymbolTable symbolTable;

	// TODO: How does this work?
	protected final DBTraceProgramViewChangeSet changes;

	protected long snap;
	protected InternalTracePlatform platform;
	protected final DBTraceTimeViewport viewport;
	protected final Runnable viewportChangeListener = this::viewportChanged;

	// This is a strange thing
	Long versionTag = 0L;

	public DBTraceProgramView(DBTrace trace, long snap, CompilerSpec compilerSpec) {
		this.trace = trace;
		this.snap = snap;
		this.languageID = compilerSpec.getLanguage().getLanguageID();
		this.language = compilerSpec.getLanguage();
		this.compilerSpec = compilerSpec;

		checkRefreshAllAddresses();

		this.viewport = trace.createTimeViewport();
		this.viewport.setSnap(snap);

		// TODO: Initialize guest platform for fixed views?
		this.platform = trace.getPlatformManager().getHostPlatform();

		this.eventQueues = new DomainObjectEventQueues(this, TIME_INTERVAL, trace.getLock());

		this.bookmarkManager = new DBTraceProgramViewBookmarkManager(this);
		this.equateTable = new DBTraceProgramViewEquateTable(this);
		this.functionManager = new DBTraceProgramViewFunctionManager(this);
		this.listing = new DBTraceProgramViewListing(this);
		this.memory = new DBTraceProgramViewMemory(this);
		this.programContext = new DBTraceProgramViewProgramContext(this);
		this.propertyMapManager = new DBTraceProgramViewPropertyMapManager(this);
		this.referenceManager = new DBTraceProgramViewReferenceManager(this);
		this.symbolTable = new DBTraceProgramViewSymbolTable(this);

		this.changes = new DBTraceProgramViewChangeSet();

	}

	protected void checkRefreshAllAddresses() {
		if (this.allAddressesValid) {
			return;
		}
		AddressSet allAddresses = new AddressSet();
		for (AddressSpace space : trace.getBaseAddressFactory().getPhysicalSpaces()) {
			if (space.getType() != AddressSpace.TYPE_OTHER) {
				allAddresses.add(space.getMinAddress(), space.getMaxAddress());
			}
		}
		this.allAddresses = allAddresses;
		this.allAddressesValid = true;
	}

	protected AddressSetView getAllAddresses() {
		checkRefreshAllAddresses();
		return allAddresses;
	}

	protected void viewportChanged() {
		eventQueues.fireEvent(new DomainObjectChangeRecord(DomainObjectEvent.RESTORED));
	}

	protected void fireEventAllViews(DomainObjectChangeRecord ev) {
		eventQueues.fireEvent(ev);
	}

	/**
	 * Fires object-restored event on this view and all associated register views.
	 */
	protected void fireObjectRestored() {
		fireEventAllViews(new DomainObjectChangeRecord(DomainObjectEvent.RESTORED));
	}

	@Override
	public String toString() {
		return String.format("<%s on %s at snap=%d>", getClass().getSimpleName(), trace, snap);
	}

	@Override
	public DBTrace getTrace() {
		return trace;
	}

	@Override
	public long getSnap() {
		return snap;
	}

	@Override
	public TraceTimeViewport getViewport() {
		return viewport;
	}

	@Override
	public Long getMaxSnap() {
		return trace.getTimeManager().getMaxSnap();
	}

	@Override
	public DBTraceProgramViewListing getListing() {
		return listing;
	}

	@Override
	public AddressMap getAddressMap() {
		return null;
	}

	@Override
	public TraceBasedDataTypeManager getDataTypeManager() {
		return platform.getDataTypeManager();
	}

	@Override
	public FunctionManager getFunctionManager() {
		return functionManager;
	}

	@Override
	public ProgramUserData getProgramUserData() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SymbolTable getSymbolTable() {
		return symbolTable;
	}

	@Override
	public ExternalManager getExternalManager() {
		throw new UnsupportedOperationException("Traces do not support externals");
	}

	@Override
	public EquateTable getEquateTable() {
		return equateTable;
	}

	@Override
	public DBTraceProgramViewMemory getMemory() {
		return memory;
	}

	@Override
	public ReferenceManager getReferenceManager() {
		return referenceManager;
	}

	@Override
	public BookmarkManager getBookmarkManager() {
		return bookmarkManager;
	}

	@Override
	public int getDefaultPointerSize() {
		return language.getDefaultDataSpace().getPointerSize();
	}

	@Override
	public String getCompiler() {
		// TODO: not yet implemented
		return "unknown";
	}

	@Override
	public void setCompiler(String compiler) {
		// TODO: not yet implemented
		throw new UnsupportedOperationException();
	}

	@Override
	public CategoryPath getPreferredRootNamespaceCategoryPath() {
		// TODO: not yet implemented
		return null;
	}

	@Override
	public void setPreferredRootNamespaceCategoryPath(String categoryPath) {
		// TODO: not yet implemented
		throw new UnsupportedOperationException();
	}

	@Override
	public String getExecutablePath() {
		return trace.getExecutablePath();
	}

	@Override
	public void setExecutablePath(String path) {
		trace.setExecutablePath(path);
	}

	@Override
	public String getExecutableFormat() {
		return "Trace";
	}

	@Override
	public void setExecutableFormat(String format) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getExecutableMD5() {
		return null;
	}

	@Override
	public void setExecutableMD5(String md5) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getExecutableSHA256() {
		return null;
	}

	@Override
	public void setExecutableSHA256(String sha256) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Date getCreationDate() {
		return trace.getCreationDate();
	}

	@Override
	public RelocationTable getRelocationTable() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public CompilerSpec getCompilerSpec() {
		return compilerSpec;
	}

	@Override
	public LanguageID getLanguageID() {
		return languageID;
	}

	@Override
	public PropertyMapManager getUsrPropertyManager() {
		return propertyMapManager;
	}

	@Override
	public ProgramContext getProgramContext() {
		return programContext;
	}

	@Override
	public Address getMinAddress() {
		return language.getAddressFactory().getAddressSet().getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return language.getAddressFactory().getAddressSet().getMaxAddress();
	}

	@Override
	public ProgramChangeSet getChanges() {
		return changes;
	}

	@Override
	public ProgramOverlayAddressSpace createOverlaySpace(String overlaySpaceName,
			AddressSpace baseSpace) throws IllegalStateException, DuplicateNameException,
			InvalidNameException, LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void renameOverlaySpace(String oldOverlaySpaceName, String newName)
			throws NotFoundException, InvalidNameException, DuplicateNameException, LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeOverlaySpace(String overlaySpaceName)
			throws LockException, NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressFactory getAddressFactory() {
		return trace.getBaseAddressFactory();
	}

	@Override
	public Address[] parseAddress(String addrStr) {
		return language.getAddressFactory().getAllAddresses(addrStr);
	}

	@Override
	public Address[] parseAddress(String addrStr, boolean caseSensitive) {
		return language.getAddressFactory().getAllAddresses(addrStr, caseSensitive);
	}

	@Override
	public Register getRegister(String name) {
		return language.getRegister(name);
	}

	@Override
	public Register getRegister(Address addr) {
		return language.getRegister(addr, 0);
	}

	@Override
	public Register[] getRegisters(Address addr) {
		return language.getRegisters(addr);
	}

	@Override
	public Register getRegister(Address addr, int size) {
		return language.getRegister(addr, size);
	}

	@Override
	public Register getRegister(Varnode varnode) {
		return language.getRegister(varnode.getAddress(), varnode.getSize());
	}

	@Override
	public Address getImageBase() {
		return language.getDefaultSpace().getMinAddress();
	}

	@Override
	public void setImageBase(Address base, boolean commit)
			throws AddressOverflowException, LockException, IllegalStateException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void restoreImageBase() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLanguage(Language language, CompilerSpecID compilerSpecID,
			boolean forceRedisassembly, TaskMonitor monitor)
			throws IllegalStateException, IncompatibleLanguageException, LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace getGlobalNamespace() {
		return trace.getSymbolManager().getGlobalNamespace();
	}

	@Override
	public AddressSetPropertyMap createAddressSetPropertyMap(String name)
			throws DuplicateNameException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public IntRangeMap createIntRangeMap(String name) throws DuplicateNameException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AddressSetPropertyMap getAddressSetPropertyMap(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public IntRangeMap getIntRangeMap(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void deleteAddressSetPropertyMap(String name) {
		// TODO Auto-generated method stub

	}

	@Override
	public void deleteIntRangeMap(String name) {
		// TODO Auto-generated method stub

	}

	@Override
	public long getUniqueProgramID() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Transaction openTransaction(String description) throws IllegalStateException {
		return trace.openTransaction(description);
	}

	@Override
	public int startTransaction(String description) {
		return trace.startTransaction(description);
	}

	@Override
	public int startTransaction(String description, AbortedTransactionListener listener) {
		return trace.startTransaction(description, listener);
	}

	@Override
	public boolean endTransaction(int transactionID, boolean commit) {
		return trace.endTransaction(transactionID, commit);
	}

	@Override
	public TransactionInfo getCurrentTransactionInfo() {
		return trace.getCurrentTransactionInfo();
	}

	@Override
	public boolean hasTerminatedTransaction() {
		return trace.hasTerminatedTransaction();
	}

	@Override
	public DomainObject[] getSynchronizedDomainObjects() {
		return trace.getSynchronizedDomainObjects();
	}

	@Override
	public void addSynchronizedDomainObject(DomainObject domainObj) throws LockException {
		trace.addSynchronizedDomainObject(domainObj);
	}

	@Override
	public void releaseSynchronizedDomainObject() throws LockException {
		trace.releaseSynchronizedDomainObject();
	}

	@Override
	public boolean isChanged() {
		return trace.isChanged();
	}

	@Override
	public void setTemporary(boolean state) {
		trace.setTemporary(state);
	}

	@Override
	public boolean isTemporary() {
		return trace.isTemporary();
	}

	@Override
	public boolean isChangeable() {
		return trace.isChangeable();
	}

	@Override
	public boolean canSave() {
		/*
		 * TODO: Trying to save the view instead of the trace causes a cast exception.... I may need
		 * to always return false here, and use my own "TraceManager" to handle saving
		 * 
		 * I might also extend DomainObjectAdapter, and create a ContentHandler for views, but that
		 * might get weird....
		 */
		return trace.canSave();
	}

	@Override
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException {
		trace.save(comment, monitor);
	}

	@Override
	public void saveToPackedFile(File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		trace.saveToPackedFile(outputFile, monitor);
	}

	protected synchronized EventTranslator getEventTranslator() {
		if (eventTranslator == null) {
			eventTranslator = new EventTranslator();
			trace.addDirectChangeListener(eventTranslator);
		}
		return eventTranslator;
	}

	@Override
	public void addListener(DomainObjectListener dol) {
		getEventTranslator();
		eventQueues.addListener(dol);
	}

	@Override
	public void removeListener(DomainObjectListener dol) {
		eventQueues.removeListener(dol);
	}

	@Override
	public void addCloseListener(DomainObjectClosedListener listener) {
		trace.addCloseListener(listener);
	}

	@Override
	public void removeCloseListener(DomainObjectClosedListener listener) {
		trace.removeCloseListener(listener);
	}

	@Override
	public void addDomainFileListener(DomainObjectFileListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeDomainFileListener(DomainObjectFileListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay) {
		getEventTranslator();
		return eventQueues.createPrivateEventQueue(listener, maxDelay);
	}

	@Override
	public boolean removePrivateEventQueue(EventQueueID id) {
		return eventQueues.removePrivateEventQueue(id);
	}

	@Override
	public String getDescription() {
		return trace.getDescription() + " (at snap " + snap + ")";
	}

	@Override
	public String getName() {
		return trace.getName() + " (snap " + snap + ")";
	}

	@Override
	public void setName(String name) {
		throw new UnsupportedOperationException("Cannot use program view to set the trace name");
	}

	@Override
	public DomainFile getDomainFile() {
		return trace.getDomainFile();
	}

	@Override
	public boolean addConsumer(Object consumer) {
		return trace.addConsumer(consumer);
	}

	@Override
	public ArrayList<Object> getConsumerList() {
		return trace.getConsumerList();
	}

	@Override
	public boolean isUsedBy(Object consumer) {
		return trace.isUsedBy(consumer);
	}

	@Override
	public void release(Object consumer) {
		trace.release(consumer);
	}

	@Override
	public void setEventsEnabled(boolean enabled) {
		eventQueues.setEventsEnabled(enabled);
	}

	@Override
	public boolean isSendingEvents() {
		return eventQueues.isSendingEvents();
	}

	@Override
	public void flushEvents() {
		eventQueues.flushEvents();
	}

	@Override
	public void flushPrivateEventQueue(EventQueueID id) {
		eventQueues.flushPrivateEventQueue(id);
	}

	@Override
	public boolean canLock() {
		return trace.canLock();
	}

	@Override
	public boolean isLocked() {
		return trace.isLocked();
	}

	@Override
	public boolean lock(String reason) {
		return trace.lock(reason);
	}

	@Override
	public void forceLock(boolean rollback, String reason) {
		trace.forceLock(rollback, reason);
	}

	@Override
	public void unlock() {
		trace.unlock();
	}

	@Override
	public List<String> getOptionsNames() {
		return trace.getOptionsNames();
	}

	@Override
	public Options getOptions(String propertyListName) {
		return trace.getOptions(propertyListName);
	}

	@Override
	public boolean isClosed() {
		return trace.isClosed();
	}

	@Override
	public boolean hasExclusiveAccess() {
		return trace.hasExclusiveAccess();
	}

	@Override
	public Map<String, String> getMetadata() {
		return trace.getMetadata();
	}

	@Override
	public long getModificationNumber() {
		return trace.getModificationNumber();
	}

	@Override
	public boolean canUndo() {
		return trace.canUndo();
	}

	@Override
	public boolean canRedo() {
		return trace.canRedo();
	}

	@Override
	public void clearUndo() {
		trace.clearUndo();
	}

	@Override
	public void undo() throws IOException {
		trace.undo();
	}

	@Override
	public void redo() throws IOException {
		trace.redo();
	}

	@Override
	public String getUndoName() {
		return trace.getUndoName();
	}

	@Override
	public String getRedoName() {
		return trace.getRedoName();
	}

	@Override
	public List<String> getAllUndoNames() {
		return trace.getAllUndoNames();
	}

	@Override
	public List<String> getAllRedoNames() {
		return trace.getAllRedoNames();
	}

	@Override
	public void addTransactionListener(TransactionListener listener) {
		trace.addTransactionListener(listener);
	}

	@Override
	public void removeTransactionListener(TransactionListener listener) {
		trace.removeTransactionListener(listener);
	}

	public void updateMemoryAddRegionBlock(TraceMemoryRegion region) {
		memory.invalidateRegions();
	}

	public void updateMemoryChangeRegionBlockName(TraceMemoryRegion region) {
		// Doesn't affect any cache
	}

	public void updateMemoryChangeRegionBlockFlags(TraceMemoryRegion region, Lifespan lifespan) {
		// Doesn't affect any cache
	}

	public void updateMemoryChangeRegionBlockRange(TraceMemoryRegion region, AddressRange oldRange,
			AddressRange newRange) {
		memory.invalidateRegions();
	}

	public void updateMemoryChangeRegionBlockLifespan(TraceMemoryRegion region,
			Lifespan oldLifespan, Lifespan newLifespan) {
		memory.invalidateRegions();
	}

	public void updateMemoryDeleteRegionBlock(TraceMemoryRegion region) {
		memory.invalidateRegions();
	}

	public void updateMemoryAddSpaceBlock(AddressSpace space) {
		// Spaces are not time-bound. No visibility check.
		memory.updateAddSpaceBlock(space);
		allAddressesValid = false;
	}

	public void updateMemoryDeleteSpaceBlock(AddressSpace space) {
		// Spaces are not time-bound. No visibility check.
		memory.updateDeleteSpaceBlock(space);
		allAddressesValid = false;
	}

	public void updateMemoryRefreshBlocks() {
		memory.updateRefreshBlocks();
	}

	public void updateBytesChanged(AddressRange range) {
		memory.updateBytesChanged(range);
	}

	protected DomainObjectEventQueues getEventQueues(AddressSpace space) {
		/**
		 * NOTE: Thought about views on other frames. IIRC, this was an abandoned experiment for
		 * "register listings"
		 */
		return eventQueues;
	}

	protected DomainObjectEventQueues isVisible(AddressSpace space,
			TraceAddressSnapRange range) {
		return viewport.containsAnyUpper(range.getLifespan()) ? getEventQueues(space) : null;
	}

	protected boolean isBookmarkVisible(TraceBookmark bm, Lifespan lifespan) {
		return viewport.containsAnyUpper(lifespan);
	}

	protected DomainObjectEventQueues isBookmarkVisible(AddressSpace space, TraceBookmark bm) {
		return isBookmarkVisible(bm, bm.getLifespan()) ? getEventQueues(space) : null;
	}

	protected boolean bytesDifferForSet(byte[] b1, byte[] b2, AddressSetView set) {
		Address min = set.getMinAddress();
		for (AddressRange rng : set) {
			int beg = (int) rng.getMinAddress().subtract(min);
			int end = beg + (int) rng.getLength();
			if (!Arrays.equals(b1, beg, end, b2, beg, end)) {
				return true;
			}
		}
		return false;
	}

	protected Occlusion<TraceCodeUnit> getCodeOcclusion(AddressSpace space) {
		return new RangeQueryOcclusion<>() {
			final DBTraceCodeSpace codeSpace = trace.getCodeManager().get(space, false);
			final DBTraceMemorySpace memSpace = trace.getMemoryManager().get(space, false);
			final DBTraceDefinedUnitsView definedUnits =
				codeSpace == null ? null : codeSpace.definedUnits();

			public boolean occluded(TraceCodeUnit cu, AddressRange range, Lifespan span) {
				if (cu == null) {
					return RangeQueryOcclusion.super.occluded(cu, range, span);
				}
				AddressSetView known =
					memSpace.getAddressesWithState(span, s -> s == TraceMemoryState.KNOWN);
				if (!known.intersects(range.getMinAddress(), range.getMaxAddress())) {
					return RangeQueryOcclusion.super.occluded(cu, range, span);
				}
				byte[] memBytes = new byte[cu.getLength()];
				memSpace.getBytes(span.lmax(), cu.getMinAddress(), ByteBuffer.wrap(memBytes));
				byte[] cuBytes;
				try {
					cuBytes = cu.getBytes();
				}
				catch (MemoryAccessException e) {
					throw new AssertionError(e);
				}
				AddressSetView intersectKnown =
					new IntersectionAddressSetView(new AddressSet(range), known);
				if (bytesDifferForSet(memBytes, cuBytes, intersectKnown)) {
					return true;
				}
				return RangeQueryOcclusion.super.occluded(cu, range, span);
			}

			@Override
			public Iterable<? extends TraceCodeUnit> query(AddressRange range, Lifespan span) {
				return definedUnits == null ? Collections.emptyList()
						: definedUnits.get(span.lmax(), range, true);
			}

			@Override
			public AddressRange range(TraceCodeUnit cu, long snap) {
				return cu.getRange();
			}
		};
	}

	protected <T extends TraceCodeUnit> T getTopCode(Address address,
			BiFunction<TraceCodeSpace, Long, T> codeFunc) {
		DBTraceCodeSpace codeSpace =
			trace.getCodeManager().getCodeSpace(address.getAddressSpace(), false);
		if (codeSpace == null) {
			return null;
		}
		return viewport.getTop(s -> {
			T t = codeFunc.apply(codeSpace, s);
			if (t != null && isCodeVisible(t, t.getLifespan())) {
				return t;
			}
			return null;
		});
	}

	protected boolean isCodeVisible(TraceCodeUnit cu, Lifespan lifespan) {
		try {
			byte[] cubytes = cu.getBytes();
			byte[] mmbytes = new byte[cubytes.length];
			memory.getBytes(cu.getAddress(), mmbytes);
			if (!Arrays.equals(cubytes, mmbytes)) {
				return false;
			}
		}
		catch (MemoryAccessException e) {
			throw new AssertionError(e);
		}
		return viewport.isCompletelyVisible(cu.getRange(), lifespan, cu,
			getCodeOcclusion(cu.getAddress().getAddressSpace()));
	}

	protected boolean isCodeVisible(AddressSpace space, TraceAddressSnapRange range) {
		return viewport.isCompletelyVisible(range.getRange(), range.getLifespan(), null,
			getCodeOcclusion(space));
	}

	protected DomainObjectEventQueues isCodeVisible(AddressSpace space, TraceCodeUnit cu) {
		if (!isCodeVisible(cu, cu.getLifespan())) {
			return null;
		}
		return getEventQueues(space);
	}

	protected boolean isSymbolWithLifespanVisible(TraceSymbolWithLifespan symbol,
			Lifespan lifespan) {
		if (!viewport.containsAnyUpper(lifespan)) {
			return false;
		}
		return true;
	}

	protected DomainObjectEventQueues isSymbolVisible(AddressSpace space, TraceSymbol symbol) {
		// NB. Most symbols do not occlude each other
		DomainObjectEventQueues queues = getEventQueues(space);
		if (queues == null) {
			return null;
		}
		if (!(symbol instanceof TraceSymbolWithLifespan)) {
			return queues;
		}
		TraceSymbolWithLifespan symWl = (TraceSymbolWithLifespan) symbol;
		return isSymbolWithLifespanVisible(symWl, symWl.getLifespan()) ? queues : null;
	}

	protected DomainObjectEventQueues isBytesVisible(AddressSpace space,
			TraceAddressSnapRange range) {
		// NB. This need not be precise....
		DomainObjectEventQueues queues = getEventQueues(space);
		if (queues == null) {
			return null;
		}
		if (!viewport.containsAnyUpper(range.getLifespan())) {
			return null;
		}
		return queues;
	}
}
