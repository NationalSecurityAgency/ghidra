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

import com.google.common.collect.Range;

import ghidra.framework.data.DomainObjectEventQueues;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.IntRangeMap;
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
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.listing.*;
import ghidra.trace.database.memory.*;
import ghidra.trace.database.symbol.DBTraceFunctionSymbolView;
import ghidra.trace.model.Trace.*;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.bookmark.TraceBookmark;
import ghidra.trace.model.bookmark.TraceBookmarkType;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.symbol.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.trace.util.TraceTimeViewport.*;
import ghidra.util.*;
import ghidra.util.datastruct.WeakValueHashMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
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

	protected class EventTranslator extends TraceDomainObjectListener {
		public EventTranslator() {
			listenForUntyped(DomainObject.DO_OBJECT_SAVED, this::eventPassthrough);
			listenForUntyped(DomainObject.DO_DOMAIN_FILE_CHANGED, this::eventPassthrough);
			listenForUntyped(DomainObject.DO_OBJECT_RENAMED, this::eventPassthrough);
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, this::objectRestored);
			listenForUntyped(DomainObject.DO_OBJECT_CLOSED, this::eventPassthrough);
			listenForUntyped(DomainObject.DO_OBJECT_ERROR, this::eventPassthrough);

			listenFor(TraceBookmarkChangeType.TYPE_ADDED, this::bookmarkTypeAdded);
			listenFor(TraceBookmarkChangeType.ADDED, this::bookmarkAdded);
			listenFor(TraceBookmarkChangeType.CHANGED, this::bookmarkChanged);
			listenFor(TraceBookmarkChangeType.LIFESPAN_CHANGED, this::bookmarkLifespanChanged);
			listenFor(TraceBookmarkChangeType.DELETED, this::bookmarkDeleted);

			listenFor(TraceCategoryChangeType.ADDED, this::categoryAdded);
			listenFor(TraceCategoryChangeType.MOVED, this::categoryMoved);
			listenFor(TraceCategoryChangeType.RENAMED, this::categoryRenamed);
			listenFor(TraceCategoryChangeType.DELETED, this::categoryDeleted);

			listenFor(TraceCodeChangeType.ADDED, this::codeAdded);
			listenFor(TraceCodeChangeType.LIFESPAN_CHANGED, this::codeLifespanChanged);
			listenFor(TraceCodeChangeType.REMOVED, this::codeRemoved);
			listenFor(TraceCodeChangeType.FRAGMENT_CHANGED, this::codeFragmentChanged);
			listenFor(TraceCodeChangeType.DATA_TYPE_REPLACED, this::codeDataTypeReplaced);
			listenFor(TraceCodeChangeType.DATA_TYPE_SETTINGS_CHANGED,
				this::codeDataTypeSettingsChanged);

			listenFor(TraceCommentChangeType.EOL_CHANGED, this::commentEolChanged);
			listenFor(TraceCommentChangeType.PLATE_CHANGED, this::commentPlateChanged);
			listenFor(TraceCommentChangeType.POST_CHANGED, this::commentPostChanged);
			listenFor(TraceCommentChangeType.PRE_CHANGED, this::commentPreChanged);
			listenFor(TraceCommentChangeType.REPEATABLE_CHANGED, this::commentRepeatableChanged);

			listenFor(TraceCompositeDataChangeType.ADDED, this::compositeDataAdded);
			listenFor(TraceCompositeDataChangeType.LIFESPAN_CHANGED,
				this::compositeLifespanChanged);
			listenFor(TraceCompositeDataChangeType.REMOVED, this::compositeDataRemoved);

			listenFor(TraceDataTypeChangeType.ADDED, this::dataTypeAdded);
			listenFor(TraceDataTypeChangeType.CHANGED, this::dataTypeChanged);
			listenFor(TraceDataTypeChangeType.REPLACED, this::dataTypeReplaced);
			listenFor(TraceDataTypeChangeType.MOVED, this::dataTypeMoved);
			listenFor(TraceDataTypeChangeType.RENAMED, this::dataTypeRenamed);
			listenFor(TraceDataTypeChangeType.DELETED, this::dataTypeDeleted);

			listenFor(TraceFunctionChangeType.CHANGED, this::functionChanged);
			listenFor(TraceFunctionChangeType.CHANGED_PURGE, this::functionChangedPurge);
			listenFor(TraceFunctionChangeType.CHANGED_INLINE, this::functionChangedInline);
			listenFor(TraceFunctionChangeType.CHANGED_NORETURN, this::functionChangedNoReturn);
			listenFor(TraceFunctionChangeType.CHANGED_CALL_FIXUP, this::functionChangedCallFixup);
			listenFor(TraceFunctionChangeType.CHANGED_RETURN, this::functionChangedReturn);
			listenFor(TraceFunctionChangeType.CHANGED_PARAMETERS, this::functionChangedParameters);
			listenFor(TraceFunctionChangeType.CHANGED_THUNK, this::functionChangedThunk);
			listenFor(TraceFunctionChangeType.CHANGED_BODY, this::functionChangedBody);
			listenFor(TraceFunctionChangeType.TAG_APPLIED, this::functionChangedTagApplied);
			listenFor(TraceFunctionChangeType.TAG_REMOVED, this::functionChangedTagRemoved);

			listenFor(TraceFunctionTagChangeType.ADDED, this::functionTagAdded);
			listenFor(TraceFunctionTagChangeType.CHANGED, this::functionTagChanged);
			listenFor(TraceFunctionTagChangeType.DELETED, this::functionTagDeleted);

			listenFor(TraceInstructionChangeType.FLOW_OVERRIDE_CHANGED,
				this::instructionFlowOverrideChanged);
			listenFor(TraceInstructionChangeType.FALL_THROUGH_OVERRIDE_CHANGED,
				this::instructionFallThroughChanged);

			listenFor(TraceMemoryBytesChangeType.CHANGED, this::memoryBytesChanged);

			listenFor(TraceMemoryRegionChangeType.ADDED, this::memoryRegionAdded);
			listenFor(TraceMemoryRegionChangeType.CHANGED, this::memoryRegionChanged);
			listenFor(TraceMemoryRegionChangeType.LIFESPAN_CHANGED,
				this::memoryRegionLifespanChanged);
			listenFor(TraceMemoryRegionChangeType.DELETED, this::memoryRegionDeleted);

			listenFor(TraceSourceArchiveChangeType.ADDED, this::sourceArchiveAdded);
			listenFor(TraceSourceArchiveChangeType.CHANGED, this::sourceArchiveChanged);

			listenFor(TraceSymbolChangeType.ADDED, this::symbolAdded);
			listenFor(TraceSymbolChangeType.SOURCE_CHANGED, this::symbolSourceChanged);
			listenFor(TraceSymbolChangeType.SET_AS_PRIMARY, this::symbolSetAsPrimary);
			listenFor(TraceSymbolChangeType.RENAMED, this::symbolRenamed);
			listenFor(TraceSymbolChangeType.PARENT_CHANGED, this::symbolParentChanged);
			listenFor(TraceSymbolChangeType.ASSOCIATION_ADDED, this::symbolAssociationAdded);
			listenFor(TraceSymbolChangeType.ASSOCIATION_REMOVED, this::symbolAssociationRemoved);
			listenFor(TraceSymbolChangeType.ADDRESS_CHANGED, this::symbolAddressChanged);
			listenFor(TraceSymbolChangeType.LIFESPAN_CHANGED, this::symbolLifespanChanged);
			listenFor(TraceSymbolChangeType.DELETED, this::symbolDeleted);
		}

		private void eventPassthrough(DomainObjectChangeRecord rec) {
			fireEventAllViews(rec);
		}

		private void objectRestored(DomainObjectChangeRecord rec) {
			versionTag++;
			fireEventAllViews(rec);
		}

		private void bookmarkTypeAdded(TraceBookmarkType type) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_BOOKMARK_TYPE_ADDED,
				null, null, type, null, null));
		}

		private void bookmarkAdded(TraceAddressSpace space, TraceBookmark bm) {
			DomainObjectEventQueues queues = isBookmarkVisible(space, bm);
			if (queues == null) {
				return;
			}
			fireBookmarkAdded(queues, bm);
		}

		protected void fireBookmarkAdded(DomainObjectEventQueues queues, TraceBookmark bm) {
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_BOOKMARK_ADDED,
				bm.getAddress(), bm.getAddress(), bm, null, null));
		}

		private void bookmarkChanged(TraceAddressSpace space, TraceBookmark bm) {
			DomainObjectEventQueues queues = isBookmarkVisible(space, bm);
			if (queues == null) {
				return;
			}
			fireBookmarkChanged(queues, bm);
		}

		protected void fireBookmarkChanged(DomainObjectEventQueues queues, TraceBookmark bm) {
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_BOOKMARK_CHANGED,
				bm.getAddress(), bm.getAddress(), bm, null, null));
		}

		private void bookmarkLifespanChanged(TraceAddressSpace space, TraceBookmark bm,
				Range<Long> oldSpan, Range<Long> newSpan) {
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

		private void bookmarkDeleted(TraceAddressSpace space, TraceBookmark bm) {
			DomainObjectEventQueues queues = isBookmarkVisible(space, bm);
			if (queues == null) {
				return;
			}
			fireBookmarkRemoved(queues, bm);
		}

		protected void fireBookmarkRemoved(DomainObjectEventQueues queues, TraceBookmark bm) {
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_BOOKMARK_REMOVED,
				bm.getAddress(), bm.getAddress(), bm, null, null));
		}

		private void categoryAdded(long id, Category oldIsNull, Category added) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_CATEGORY_ADDED, null,
				null, null, oldIsNull, added));
		}

		private void categoryMoved(long id, CategoryPath oldPath, CategoryPath newPath) {
			Category category = getDataTypeManager().getCategory(id);
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_CATEGORY_MOVED, null,
				null, null, oldPath, category));
		}

		private void categoryRenamed(long id, String oldName, String newName) {
			Category category = getDataTypeManager().getCategory(id);
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_CATEGORY_RENAMED, null,
				null, null, oldName, category));
		}

		private void categoryDeleted(long id, CategoryPath deleted, CategoryPath newIsNull) {
			Category parent = getDataTypeManager().getCategory(deleted.getParent());
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_CATEGORY_REMOVED, null,
				null, null, parent, deleted.getName()));
		}

		private void codeAdded(TraceAddressSpace space, TraceAddressSnapRange range,
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
				new ProgramChangeRecord(ChangeManager.DOCR_CODE_ADDED, min, max, null, null, null));
		}

		private void codeLifespanChanged(TraceAddressSpace space, TraceCodeUnit unit,
				Range<Long> oldSpan, Range<Long> newSpan) {
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

		private void codeRemoved(TraceAddressSpace space, TraceAddressSnapRange range,
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
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_CODE_REMOVED,
				min, max, null, removed, null));
		}

		private void codeFragmentChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				ProgramFragment oldFragment, ProgramFragment newFragment) {
			DomainObjectEventQueues queues = isVisible(space, range);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_CODE_MOVED, null, null,
				null, range.getX1(), range.getX2()));
		}

		private void codeDataTypeReplaced(TraceAddressSpace space, TraceAddressSnapRange range,
				Long oldDataTypeID, Long newDataTypeID) {
			// TODO??: "code" visibility check may not be necessary or advantageous
			DomainObjectEventQueues queues = isVisible(space, range);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_DATA_TYPE_REPLACED,
				range.getX1(), range.getX2(), null, null, null));
		}

		private void codeDataTypeSettingsChanged(TraceAddressSpace space,
				TraceAddressSnapRange range) {
			DomainObjectEventQueues queues = isVisible(space, range);
			if (queues == null) {
				return;
			}
			// Yes, x1 twice
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED,
				range.getX1(), range.getX1(), null, null, null));
		}

		private void commentChanged(int docrType, TraceAddressSpace space,
				TraceAddressSnapRange range,
				String oldValue, String newValue) {
			DomainObjectEventQueues queues = isVisible(space, range);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(docrType,
				range.getX1(), range.getX2(), null, oldValue, newValue));
		}

		private void commentEolChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			commentChanged(ChangeManager.DOCR_EOL_COMMENT_CHANGED, space, range, oldValue,
				newValue);
		}

		private void commentPlateChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			commentChanged(ChangeManager.DOCR_PLATE_COMMENT_CHANGED, space, range, oldValue,
				newValue);
		}

		private void commentPostChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			commentChanged(ChangeManager.DOCR_POST_COMMENT_CHANGED, space, range, oldValue,
				newValue);
		}

		private void commentPreChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			commentChanged(ChangeManager.DOCR_PRE_COMMENT_CHANGED, space, range, oldValue,
				newValue);
		}

		private void commentRepeatableChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				String oldValue, String newValue) {
			// TODO: The "repeatable" semantics are not implemented, yet.
			commentChanged(ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED, space, range, oldValue,
				newValue);
		}

		private void compositeDataAdded(TraceAddressSpace space, TraceAddressSnapRange range,
				TraceData oldIsNull, TraceData added) {
			DomainObjectEventQueues queues = isCodeVisible(space, added);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_COMPOSITE_ADDED,
				added.getMinAddress(), added.getMaxAddress(), null, null, added));
		}

		private void compositeLifespanChanged(TraceAddressSpace space, TraceData data,
				Range<Long> oldSpan, Range<Long> newSpan) {
			DomainObjectEventQueues queues = getEventQueues(space);
			if (queues == null) {
				return;
			}
			boolean inOld = isCodeVisible(data, oldSpan);
			boolean inNew = isCodeVisible(data, newSpan);
			if (inOld && !inNew) {
				queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_COMPOSITE_REMOVED,
					data.getMinAddress(), data.getMaxAddress(), null, data, null));
			}
			if (!inOld && inNew) {
				queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_COMPOSITE_ADDED,
					data.getMinAddress(), data.getMaxAddress(), null, null, data));
			}
		}

		private void compositeDataRemoved(TraceAddressSpace space, TraceAddressSnapRange range,
				TraceData removed, TraceData newIsNull) {
			DomainObjectEventQueues queues = isCodeVisible(space, removed);
			if (queues == null) {
				return;
			}
			// TODO: ProgramDB doesn't send this.... Should I?
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_COMPOSITE_REMOVED,
				removed.getMinAddress(), removed.getMaxAddress(), null, removed, null));
		}

		private void dataTypeAdded(long id, DataType oldIsNull, DataType added) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_DATA_TYPE_ADDED, null,
				null, null, oldIsNull, added));
		}

		private void dataTypeChanged(long id, DataType oldIsNull, DataType changed) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_DATA_TYPE_CHANGED,
				null, null, null, oldIsNull, changed));
		}

		private void dataTypeReplaced(long id, DataTypePath oldPath, DataTypePath newPath) {
			DataType newType = getDataTypeManager().getDataType(id);
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_DATA_TYPE_REPLACED,
				null, null, null, newPath, newType));
		}

		private void dataTypeMoved(long id, DataTypePath oldPath, DataTypePath newPath) {
			Category oldCategory = getDataTypeManager().getCategory(oldPath.getCategoryPath());
			DataType dataType = getDataTypeManager().getDataType(id);
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_DATA_TYPE_MOVED, null,
				null, null, oldCategory, dataType));
		}

		private void dataTypeRenamed(long id, String oldName, String newName) {
			DataType dataType = getDataTypeManager().getDataType(id);
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_DATA_TYPE_RENAMED,
				null, null, null, oldName, dataType));
		}

		private void dataTypeDeleted(long id, DataTypePath oldPath, DataTypePath newIsNull) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_DATA_TYPE_REMOVED,
				null, null, null, oldPath, newIsNull));
		}

		private void gatherThunksTo(Collection<TraceFunctionSymbol> into,
				TraceFunctionSymbol function) {
			into.add(function);
			for (Address address : function.getFunctionThunkAddresses()) {
				TraceFunctionSymbol thunkTo = functionManager.getFunctionAt(address);
				if (thunkTo != null) {
					gatherThunksTo(into, thunkTo);
				}
			}
		}

		private Collection<TraceFunctionSymbol> gatherThunksTo(TraceFunctionSymbol function) {
			List<TraceFunctionSymbol> result = new ArrayList<>();
			gatherThunksTo(result, function);
			return result;
		}

		private void functionChangedGeneric(TraceAddressSpace space, TraceFunctionSymbol function,
				int type, int subType) {
			DomainObjectEventQueues queues = isFunctionVisible(space, function);
			if (queues == null) {
				return;
			}
			for (TraceFunctionSymbol f : gatherThunksTo(function)) {
				queues.fireEvent(new ProgramChangeRecord(type, subType, f.getEntryPoint(),
					f.getEntryPoint(), f, null, null));
			}
		}

		private void functionChanged(TraceAddressSpace space, TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_FUNCTION_CHANGED, 0);
		}

		private void functionChangedPurge(TraceAddressSpace space, TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_FUNCTION_CHANGED,
				ChangeManager.FUNCTION_CHANGED_PURGE);
		}

		private void functionChangedInline(TraceAddressSpace space, TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_FUNCTION_CHANGED,
				ChangeManager.FUNCTION_CHANGED_INLINE);
		}

		private void functionChangedNoReturn(TraceAddressSpace space,
				TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_FUNCTION_CHANGED,
				ChangeManager.FUNCTION_CHANGED_NORETURN);
		}

		private void functionChangedCallFixup(TraceAddressSpace space,
				TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_FUNCTION_CHANGED,
				ChangeManager.FUNCTION_CHANGED_CALL_FIXUP);
		}

		private void functionChangedReturn(TraceAddressSpace space, TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_FUNCTION_CHANGED,
				ChangeManager.FUNCTION_CHANGED_RETURN);
		}

		private void functionChangedParameters(TraceAddressSpace space,
				TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_FUNCTION_CHANGED,
				ChangeManager.FUNCTION_CHANGED_PARAMETERS);
		}

		private void functionChangedThunk(TraceAddressSpace space, TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_FUNCTION_CHANGED,
				ChangeManager.FUNCTION_CHANGED_THUNK);
		}

		private void functionChangedBody(TraceAddressSpace space, TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_FUNCTION_BODY_CHANGED, 0);
		}

		private void functionChangedTagApplied(TraceAddressSpace space,
				TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_TAG_ADDED_TO_FUNCTION, 0);
		}

		private void functionChangedTagRemoved(TraceAddressSpace space,
				TraceFunctionSymbol function) {
			functionChangedGeneric(space, function, ChangeManager.DOCR_TAG_REMOVED_FROM_FUNCTION,
				0);
		}

		private void functionTagAdded(FunctionTag tag) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_FUNCTION_TAG_CREATED,
				null, null, tag, null, null));
		}

		private void functionTagChanged(FunctionTag tag) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_FUNCTION_TAG_CHANGED,
				null, null, tag, null, null));
		}

		private void functionTagDeleted(FunctionTag tag) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_FUNCTION_TAG_DELETED,
				null, null, tag, null, null));
		}

		private void instructionFlowOverrideChanged(TraceAddressSpace space,
				TraceInstruction instruction, FlowOverride oldOverride, FlowOverride newOverride) {
			DomainObjectEventQueues queues = isCodeVisible(space, instruction);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_FLOWOVERRIDE_CHANGED,
				instruction.getMinAddress(), instruction.getMinAddress(), null, null, null));
		}

		private void instructionFallThroughChanged(TraceAddressSpace space,
				TraceInstruction instruction, boolean oldFallThrough, boolean newFallThrough) {
			DomainObjectEventQueues queues = isCodeVisible(space, instruction);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_FALLTHROUGH_CHANGED,
				instruction.getMinAddress(), instruction.getMaxAddress(), null, null, null));
		}

		private void memoryBytesChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				byte[] oldIsNull, byte[] bytes) {
			DomainObjectEventQueues queues = isBytesVisible(space, range);
			if (queues == null) {
				return;
			}
			fireMemoryBytesChanged(queues, range);
		}

		protected void fireMemoryBytesChanged(DomainObjectEventQueues queues,
				TraceAddressSnapRange range) {
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_MEMORY_BYTES_CHANGED,
				range.getX1(), range.getX2(), null, null, null));
		}

		private void memoryRegionAdded(TraceAddressSpace space, TraceMemoryRegion region) {
			if (!isRegionVisible(region)) {
				return;
			}
			// NOTE: Register view regions are fixed
			eventQueues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_MEMORY_BLOCK_ADDED,
				region.getMinAddress(), region.getMaxAddress(), null, null, null));
			// NOTE: MemoryMapDB does this, too. Otherwise, CodeBrowserPlugin does not hear.
			eventQueues.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
		}

		private void memoryRegionChanged(TraceAddressSpace space, TraceMemoryRegion region) {
			if (!isRegionVisible(region)) {
				return;
			}
			eventQueues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_MEMORY_BLOCK_CHANGED,
				region.getMinAddress(), region.getMaxAddress(), null, null, null));
			// TODO: Perhaps a bit heavy-handed here. MemoryMapDB does not do this, too.
			// TODO: Probably want a separate RANGE_CHANGED or MOVED event
			eventQueues.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
		}

		private void memoryRegionLifespanChanged(TraceAddressSpace space, TraceMemoryRegion region,
				Range<Long> oldSpan, Range<Long> newSpan) {
			boolean inOld = isRegionVisible(region, oldSpan);
			boolean inNew = isRegionVisible(region, newSpan);
			if (inOld && !inNew) {
				eventQueues.fireEvent(
					new ProgramChangeRecord(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED,
						region.getMinAddress(), region.getMaxAddress(), null, null, null));
				// NOTE: MemoryMapDB does this, too. Otherwise, CodeBrowserPlugin does not hear.
				eventQueues.fireEvent(
					new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
			}
			if (!inOld && inNew) {
				eventQueues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_MEMORY_BLOCK_ADDED,
					region.getMinAddress(), region.getMaxAddress(), null, null, null));
				// NOTE: MemoryMapDB does this, too. Otherwise, CodeBrowserPlugin does not hear.
				eventQueues.fireEvent(
					new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
			}
		}

		private void memoryRegionDeleted(TraceAddressSpace space, TraceMemoryRegion region) {
			// HACK
			listing.fragmentsByRegion.remove(region);
			// END HACK
			if (!isRegionVisible(region)) {
				return;
			}
			eventQueues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED,
				region.getMinAddress(), region.getMaxAddress(), null, null, null));
			// NOTE: MemoryMapDB does this, too. Otherwise, CodeBrowserPlugin does not hear.
			eventQueues.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
		}

		private void sourceArchiveAdded(UniversalID id) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_SOURCE_ARCHIVE_ADDED,
				null, null, id, null, null));
		}

		private void sourceArchiveChanged(UniversalID id) {
			fireEventAllViews(new ProgramChangeRecord(ChangeManager.DOCR_SOURCE_ARCHIVE_CHANGED,
				null, null, id, null, null));
		}

		private void checkVariableFunctionChanged(TraceAddressSpace space, TraceSymbol symbol) {
			if (!(symbol instanceof TraceVariableSymbol)) {
				return;
			}
			TraceFunctionSymbol function = ((TraceVariableSymbol) symbol).getFunction();
			if (function == null) {
				return;
			}
			int subType = symbol instanceof TraceParameterSymbol ? //
					ChangeManager.FUNCTION_CHANGED_PARAMETERS : 0;
			for (TraceFunctionSymbol f : gatherThunksTo(function)) {
				// NOTE: Should probably not see functions in register views anyway...
				DomainObjectEventQueues queues = getEventQueues(space);
				if (queues == null) {
					continue;
				}
				queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_FUNCTION_CHANGED,
					subType, f.getEntryPoint(), f.getEntryPoint(), f, null, null));
			}
		}

		private void symbolAdded(TraceAddressSpace space, TraceSymbol symbol) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			fireSymbolAdded(queues, symbol);
			if (symbol instanceof TraceFunctionSymbol) {
				TraceFunctionSymbol function = (TraceFunctionSymbol) symbol;
				queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_FUNCTION_ADDED,
					function.getEntryPoint(), function.getEntryPoint(), function, null, null));
			}
			checkVariableFunctionChanged(space, symbol);
		}

		public void fireSymbolAdded(DomainObjectEventQueues queues, TraceSymbol symbol) {
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_SYMBOL_ADDED,
				symbol.getAddress(), symbol.getAddress(), null, null, symbol));
		}

		private void symbolSourceChanged(TraceAddressSpace space, TraceSymbol symbol) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_SYMBOL_SOURCE_CHANGED,
				symbol.getAddress(), symbol.getAddress(), symbol, null, null));
			checkVariableFunctionChanged(space, symbol);
		}

		private void symbolSetAsPrimary(TraceAddressSpace space, TraceSymbol symbol,
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
			newQueues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_SYMBOL_SET_AS_PRIMARY,
				symbol.getAddress(), symbol.getAddress(), null, oldPrimary, newPrimary));
			checkVariableFunctionChanged(space, symbol);
		}

		private void symbolRenamed(TraceAddressSpace space, TraceSymbol symbol, String oldName,
				String newName) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_SYMBOL_RENAMED,
				symbol.getAddress(), symbol.getAddress(), symbol, oldName, newName));
			checkVariableFunctionChanged(space, symbol);
		}

		private void symbolParentChanged(TraceAddressSpace space, TraceSymbol symbol,
				TraceNamespaceSymbol oldParent, TraceNamespaceSymbol newParent) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_SYMBOL_SCOPE_CHANGED,
				symbol.getAddress(), symbol.getAddress(), symbol, oldParent, newParent));
			checkVariableFunctionChanged(space, symbol);
		}

		private void symbolAssociationAdded(TraceAddressSpace space, TraceSymbol symbol,
				TraceReference oldRefIsNull, TraceReference newRef) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			// Strange. This is fired as if by the reference rather than the symbol
			queues.fireEvent(
				new ProgramChangeRecord(ChangeManager.DOCR_SYMBOL_ASSOCIATION_ADDED,
					newRef.getFromAddress(), newRef.getFromAddress(), newRef, null, symbol));
		}

		private void symbolAssociationRemoved(TraceAddressSpace space, TraceSymbol symbol,
				TraceReference oldRef, TraceReference newRefIsNull) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			// Ditto as ADDED
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_SYMBOL_ASSOCIATION_REMOVED,
				oldRef.getFromAddress(), oldRef.getFromAddress(), oldRef, symbol, null));
		}

		private void symbolAddressChanged(TraceAddressSpace space, TraceSymbol symbol,
				Address oldAddress, Address newAddress) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED,
				oldAddress, oldAddress, symbol, oldAddress, newAddress));
			checkVariableFunctionChanged(space, symbol);
		}

		private void symbolLifespanChanged(TraceAddressSpace space, TraceSymbolWithLifespan symbol,
				Range<Long> oldSpan, Range<Long> newSpan) {
			DomainObjectEventQueues queues = getEventQueues(space);
			if (queues == null) {
				return;
			}
			boolean inOld = isSymbolWithLifespanVisible(symbol, oldSpan);
			boolean inNew = isSymbolWithLifespanVisible(symbol, newSpan);
			if (inOld && !inNew) {
				fireSymbolRemoved(queues, symbol);
				if (symbol instanceof TraceFunctionSymbol) {
					TraceFunctionSymbol function = (TraceFunctionSymbol) symbol;
					queues.fireEvent(new ProgramChangeRecord(
						ChangeManager.DOCR_FUNCTION_REMOVED, function.getEntryPoint(),
						function.getEntryPoint(), function, function.getBody(), null));
				}
			}
			if (!inOld && inNew) {
				fireSymbolAdded(queues, symbol);
				if (symbol instanceof TraceFunctionSymbol) {
					TraceFunctionSymbol function = (TraceFunctionSymbol) symbol;
					queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_FUNCTION_ADDED,
						function.getEntryPoint(), function.getEntryPoint(), function, null, null));
				}
			}
		}

		private void symbolDeleted(TraceAddressSpace space, TraceSymbol symbol) {
			DomainObjectEventQueues queues = isSymbolVisible(space, symbol);
			if (queues == null) {
				return;
			}
			fireSymbolRemoved(queues, symbol);
			if (symbol instanceof TraceFunctionSymbol) {
				TraceFunctionSymbol function = (TraceFunctionSymbol) symbol;
				queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_FUNCTION_REMOVED,
					function.getEntryPoint(), function.getEntryPoint(), function,
					function.getBody(), null));
			}
			checkVariableFunctionChanged(space, symbol);
		}

		protected void fireSymbolRemoved(DomainObjectEventQueues queues, TraceSymbol symbol) {
			queues.fireEvent(new ProgramChangeRecord(ChangeManager.DOCR_SYMBOL_REMOVED,
				symbol.getAddress(), symbol.getAddress(), symbol, symbol.getName(),
				symbol.getID()));
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
	protected final AddressSet allAddresses = new AddressSet();

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

	protected final Map<TraceThread, DBTraceProgramViewRegisters> regViewsByThread;

	protected long snap;
	protected final DefaultTraceTimeViewport viewport;
	protected final Runnable viewportChangeListener = this::viewportChanged;

	// This is a strange thing
	Long versionTag = 0L;

	public DBTraceProgramView(DBTrace trace, long snap, CompilerSpec compilerSpec) {
		for (AddressSpace space : trace.getBaseAddressFactory().getPhysicalSpaces()) {
			if (space.getType() == AddressSpace.TYPE_OTHER) {
				continue;
			}
			allAddresses.add(space.getMinAddress(), space.getMaxAddress());
		}
		this.trace = trace;
		this.snap = snap;
		this.languageID = compilerSpec.getLanguage().getLanguageID();
		this.language = compilerSpec.getLanguage();
		this.compilerSpec = compilerSpec;

		this.viewport = new DefaultTraceTimeViewport(trace);
		this.viewport.setSnap(snap);

		this.eventQueues =
			new DomainObjectEventQueues(this, TIME_INTERVAL, BUF_SIZE, trace.getLock());

		this.regViewsByThread = new WeakValueHashMap<>();

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

	protected void viewportChanged() {
		eventQueues.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
	}

	protected void fireEventAllViews(DomainObjectChangeRecord ev) {
		// TODO: Do I need to make copies?
		eventQueues.fireEvent(ev);
		for (DBTraceProgramViewRegisters regView : regViewsByThread.values()) {
			regView.eventQueues.fireEvent(ev);
		}
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
	public DBTraceProgramViewRegisters getViewRegisters(TraceThread thread,
			boolean createIfAbsent) {
		synchronized (regViewsByThread) {
			DBTraceProgramViewRegisters regView = regViewsByThread.get(thread);
			if (regView != null) {
				return regView;
			}
			assert trace.getThreadManager().getAllThreads().contains(thread);
			DBTraceCodeRegisterSpace codeSpace =
				trace.getCodeManager().getCodeRegisterSpace(thread, createIfAbsent);
			if (codeSpace == null) {
				return null;
			}
			DBTraceMemoryRegisterSpace memorySpace =
				trace.getMemoryManager().getMemoryRegisterSpace(thread, createIfAbsent);
			if (memorySpace == null) {
				return null;
			}
			regView = new DBTraceProgramViewRegisters(this, codeSpace, memorySpace);
			regViewsByThread.put(thread, regView);
			return regView;
		}
	}

	@Override
	public AddressMap getAddressMap() {
		return null;
	}

	@Override
	public TraceBasedDataTypeManager getDataTypeManager() {
		return trace.getDataTypeManager();
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
		return null;
	}

	@Override
	public void setCompiler(String compiler) {
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
	public void invalidate() {
		// TODO: I imagine I'll find out who uses this pretty quick....
		throw new UnsupportedOperationException();
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
		return language.getAddressFactory().getAddressSet().getMinAddress();
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
	public int startTransaction(String description) {
		return trace.startTransaction(description);
	}

	@Override
	public int startTransaction(String description, AbortedTransactionListener listener) {
		return trace.startTransaction(description, listener);
	}

	@Override
	public void endTransaction(int transactionID, boolean commit) {
		trace.endTransaction(transactionID, commit);
	}

	@Override
	public Transaction getCurrentTransaction() {
		return trace.getCurrentTransaction();
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
			trace.addListener(eventTranslator);
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
	public void addTransactionListener(TransactionListener listener) {
		trace.addTransactionListener(listener);
	}

	@Override
	public void removeTransactionListener(TransactionListener listener) {
		trace.removeTransactionListener(listener);
	}

	public void updateMemoryAddBlock(DBTraceMemoryRegion region) {
		if (!isRegionVisible(region)) {
			return;
		}
		memory.updateAddBlock(region);
	}

	public void updateMemoryChangeBlockName(DBTraceMemoryRegion region) {
		if (!isRegionVisible(region)) {
			return;
		}
		memory.updateChangeBlockName(region);
	}

	public void updateMemoryChangeBlockFlags(DBTraceMemoryRegion region) {
		if (!isRegionVisible(region)) {
			return;
		}
		memory.updateChangeBlockFlags(region);
	}

	public void updateMemoryChangeBlockRange(DBTraceMemoryRegion region, AddressRange oldRange,
			AddressRange newRange) {
		if (!isRegionVisible(region)) {
			return;
		}
		memory.updateChangeBlockRange(region, oldRange, newRange);
	}

	public void updateMemoryChangeBlockLifespan(DBTraceMemoryRegion region,
			Range<Long> oldLifespan, Range<Long> newLifespan) {
		boolean inOld = isRegionVisible(region, oldLifespan);
		boolean inNew = isRegionVisible(region, newLifespan);
		if (inOld && !inNew) {
			memory.updateDeleteBlock(region);
		}
		if (!inOld && inNew) {
			memory.updateAddBlock(region);
		}
	}

	public void updateMemoryDeleteBlock(DBTraceMemoryRegion region) {
		if (!isRegionVisible(region)) {
			return;
		}
		memory.updateAddBlock(region);
	}

	public void updateMemoryRefreshBlocks() {
		memory.updateRefreshBlocks();
	}

	protected DomainObjectEventQueues getEventQueues(TraceAddressSpace space) {
		// TODO: Should there be views on other frames?
		// IIRC, this was an abandoned experiment for "register listings"
		TraceThread thread = space == null ? null : space.getThread();
		if (thread == null) {
			return eventQueues;
		}
		DBTraceProgramViewRegisters viewRegisters;
		synchronized (regViewsByThread) {
			viewRegisters = regViewsByThread.get(thread);
		}
		return viewRegisters == null ? null : viewRegisters.eventQueues;
	}

	protected DomainObjectEventQueues isVisible(TraceAddressSpace space,
			TraceAddressSnapRange range) {
		return viewport.containsAnyUpper(range.getLifespan()) ? getEventQueues(space) : null;
	}

	protected boolean isBookmarkVisible(TraceBookmark bm, Range<Long> lifespan) {
		return viewport.containsAnyUpper(lifespan);
	}

	protected DomainObjectEventQueues isBookmarkVisible(TraceAddressSpace space, TraceBookmark bm) {
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

	protected Occlusion<TraceCodeUnit> getCodeOcclusion(TraceAddressSpace space) {
		return new RangeQueryOcclusion<>() {
			final DBTraceCodeSpace codeSpace = trace.getCodeManager().get(space, false);
			final DBTraceMemorySpace memSpace = trace.getMemoryManager().get(space, false);
			final DBTraceDefinedUnitsView definedUnits =
				codeSpace == null ? null : codeSpace.definedUnits();

			public boolean occluded(TraceCodeUnit cu, AddressRange range, Range<Long> span) {
				if (cu == null) {
					return RangeQueryOcclusion.super.occluded(cu, range, span);
				}
				AddressSetView known =
					memSpace.getAddressesWithState(span, s -> s == TraceMemoryState.KNOWN);
				if (!known.intersects(range.getMinAddress(), range.getMaxAddress())) {
					return RangeQueryOcclusion.super.occluded(cu, range, span);
				}
				byte[] memBytes = new byte[cu.getLength()];
				memSpace.getBytes(span.upperEndpoint(), cu.getMinAddress(),
					ByteBuffer.wrap(memBytes));
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
			public Iterable<? extends TraceCodeUnit> query(AddressRange range, Range<Long> span) {
				return definedUnits == null
						? Collections.emptyList()
						: definedUnits.get(span.upperEndpoint(), range, true);
			}

			@Override
			public AddressRange range(TraceCodeUnit cu) {
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

	protected boolean isCodeVisible(TraceCodeUnit cu, Range<Long> lifespan) {
		return viewport.isCompletelyVisible(cu.getRange(), lifespan, cu,
			getCodeOcclusion(cu.getTraceSpace()));
	}

	protected boolean isCodeVisible(TraceAddressSpace space, TraceAddressSnapRange range) {
		return viewport.isCompletelyVisible(range.getRange(), range.getLifespan(), null,
			getCodeOcclusion(space));
	}

	protected DomainObjectEventQueues isCodeVisible(TraceAddressSpace space, TraceCodeUnit cu) {
		if (!isCodeVisible(cu, cu.getLifespan())) {
			return null;
		}
		return getEventQueues(space);
	}

	protected Occlusion<TraceFunctionSymbol> getFunctionOcclusion(TraceFunctionSymbol func) {
		return new QueryOcclusion<>() {
			DBTraceFunctionSymbolView functions = trace.getSymbolManager().functions();
			AddressSetView body = func.getBody();

			@Override
			public Iterable<? extends TraceFunctionSymbol> query(AddressRange range,
					Range<Long> span) {
				// NB. No functions in register space!
				return functions.getIntersecting(Range.singleton(span.upperEndpoint()), null, range,
					false);
			}

			public boolean itemOccludes(AddressRange range, TraceFunctionSymbol f) {
				return body.intersects(f.getBody());
			}

			@Override
			public void removeItem(AddressSet remains, TraceFunctionSymbol t) {
				remains.delete(t.getBody());
			}
		};
	}

	protected boolean isFunctionVisible(TraceFunctionSymbol function, Range<Long> lifespan) {
		AddressSetView body = function.getBody();
		AddressRange bodySpan =
			new AddressRangeImpl(body.getMinAddress(), body.getMaxAddress());
		return viewport.isCompletelyVisible(bodySpan, function.getLifespan(), function,
			getFunctionOcclusion(function));
	}

	protected DomainObjectEventQueues isFunctionVisible(TraceAddressSpace space,
			TraceFunctionSymbol function) {
		DomainObjectEventQueues queues = getEventQueues(space);
		if (queues == null) {
			return null;
		}
		return isFunctionVisible(function, function.getLifespan()) ? queues : null;
	}

	protected boolean isSymbolWithLifespanVisible(TraceSymbolWithLifespan symbol,
			Range<Long> lifespan) {
		if (symbol instanceof TraceFunctionSymbol) {
			TraceFunctionSymbol func = (TraceFunctionSymbol) symbol;
			return isFunctionVisible(func, lifespan);
		}
		if (!viewport.containsAnyUpper(lifespan)) {
			return false;
		}
		return true;
	}

	protected DomainObjectEventQueues isSymbolVisible(TraceAddressSpace space,
			TraceSymbol symbol) {
		// NB. Most symbols do not occlude each other
		DomainObjectEventQueues queues = getEventQueues(space);
		if (queues == null) {
			return null;
		}
		if (symbol instanceof TraceVariableSymbol) {
			TraceVariableSymbol var = (TraceVariableSymbol) symbol;
			TraceFunctionSymbol func = var.getFunction();
			if (func == null) {
				return queues;
			}
			return isFunctionVisible(space, func);
		}
		if (!(symbol instanceof TraceSymbolWithLifespan)) {
			return queues;
		}
		TraceSymbolWithLifespan symWl = (TraceSymbolWithLifespan) symbol;
		return isSymbolWithLifespanVisible(symWl, symWl.getLifespan()) ? queues : null;
	}

	protected DomainObjectEventQueues isBytesVisible(TraceAddressSpace space,
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

	protected Occlusion<TraceMemoryRegion> regionOcclusion = new RangeQueryOcclusion<>() {
		@Override
		public Iterable<? extends TraceMemoryRegion> query(AddressRange range, Range<Long> span) {
			return trace.getMemoryManager()
					.getRegionsIntersecting(Range.singleton(span.upperEndpoint()), range);
		}

		@Override
		public AddressRange range(TraceMemoryRegion r) {
			return r.getRange();
		}
	};

	protected boolean isRegionVisible(TraceMemoryRegion reg) {
		return isRegionVisible(reg, reg.getLifespan());
	}

	protected boolean isRegionVisible(TraceMemoryRegion reg, Range<Long> lifespan) {
		return viewport.isCompletelyVisible(reg.getRange(), lifespan, reg,
			regionOcclusion);
	}
}
