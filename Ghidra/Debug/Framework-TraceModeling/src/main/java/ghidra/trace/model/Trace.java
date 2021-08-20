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
package ghidra.trace.model;

import java.util.*;

import javax.swing.ImageIcon;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.model.bookmark.*;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointManager;
import ghidra.trace.model.context.TraceRegisterContextManager;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.trace.model.language.TraceLanguageManager;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackManager;
import ghidra.trace.model.symbol.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.trace.util.DefaultTraceChangeType;
import ghidra.util.LockHold;
import ghidra.util.UniversalID;
import resources.ResourceManager;

public interface Trace extends DataTypeManagerDomainObject {
	ImageIcon TRACE_ICON = ResourceManager.loadImage("images/video-x-generic16.png");

	public static final class TraceBookmarkChangeType<T, U> extends DefaultTraceChangeType<T, U> {
		public static final TraceBookmarkChangeType<TraceBookmarkType, Void> TYPE_ADDED =
			new TraceBookmarkChangeType<>();
		public static final TraceBookmarkChangeType<TraceBookmark, Void> ADDED =
			new TraceBookmarkChangeType<>();
		public static final TraceBookmarkChangeType<TraceBookmark, Void> CHANGED =
			new TraceBookmarkChangeType<>();
		public static final TraceBookmarkChangeType<TraceBookmark, Range<Long>> LIFESPAN_CHANGED =
			new TraceBookmarkChangeType<>();
		public static final TraceBookmarkChangeType<TraceBookmark, Void> DELETED =
			new TraceBookmarkChangeType<>();
	}

	public static final class TraceBreakpointChangeType<U>
			extends DefaultTraceChangeType<TraceBreakpoint, U> {
		public static final TraceBreakpointChangeType<Void> ADDED =
			new TraceBreakpointChangeType<>();
		public static final TraceBreakpointChangeType<Void> CHANGED =
			new TraceBreakpointChangeType<>();
		public static final TraceBreakpointChangeType<Range<Long>> LIFESPAN_CHANGED =
			new TraceBreakpointChangeType<>();
		public static final TraceBreakpointChangeType<Void> DELETED =
			new TraceBreakpointChangeType<>();
	}

	public static final class TraceCategoryChangeType<U> extends DefaultTraceChangeType<Long, U> {
		// Long is category ID
		public static final TraceCategoryChangeType<Category> ADDED =
			new TraceCategoryChangeType<>();
		public static final TraceCategoryChangeType<CategoryPath> MOVED =
			new TraceCategoryChangeType<>();
		public static final TraceCategoryChangeType<String> RENAMED =
			new TraceCategoryChangeType<>();
		public static final TraceCategoryChangeType<CategoryPath> DELETED =
			new TraceCategoryChangeType<>();
	}

	public static final class TraceCodeChangeType<T, U> extends DefaultTraceChangeType<T, U> {
		// May be a single unit or a whole block. "newValue" is first unit
		public static final TraceCodeChangeType<TraceAddressSnapRange, TraceCodeUnit> ADDED =
			new TraceCodeChangeType<>();
		public static final TraceCodeChangeType<TraceCodeUnit, Range<Long>> LIFESPAN_CHANGED =
			new TraceCodeChangeType<>();
		// May be a single unit or a coalesced range. "oldValue" is null or first unit
		public static final TraceCodeChangeType<TraceAddressSnapRange, TraceCodeUnit> REMOVED =
			new TraceCodeChangeType<>();
		// TODO: Probably make a TraceFragment?
		// TODO: Probably a separate change type for tree changes
		public static final TraceCodeChangeType<TraceAddressSnapRange, ProgramFragment> FRAGMENT_CHANGED =
			new TraceCodeChangeType<>();
		// Long is data type ID
		public static final TraceCodeChangeType<TraceAddressSnapRange, Long> DATA_TYPE_REPLACED =
			new TraceCodeChangeType<>();
		public static final TraceCodeChangeType<TraceAddressSnapRange, Void> DATA_TYPE_SETTINGS_CHANGED =
			new TraceCodeChangeType<>();
	}

	public static final class TraceCommentChangeType
			extends DefaultTraceChangeType<TraceAddressSnapRange, String> {
		private static final Map<Integer, TraceCommentChangeType> BY_TYPE = new HashMap<>();

		public static final TraceCommentChangeType PLATE_CHANGED =
			new TraceCommentChangeType(CodeUnit.PLATE_COMMENT);
		public static final TraceCommentChangeType PRE_CHANGED =
			new TraceCommentChangeType(CodeUnit.PRE_COMMENT);
		public static final TraceCommentChangeType POST_CHANGED =
			new TraceCommentChangeType(CodeUnit.POST_COMMENT);
		public static final TraceCommentChangeType EOL_CHANGED =
			new TraceCommentChangeType(CodeUnit.EOL_COMMENT);
		public static final TraceCommentChangeType REPEATABLE_CHANGED =
			new TraceCommentChangeType(CodeUnit.REPEATABLE_COMMENT);

		public static TraceCommentChangeType byType(int type) {
			return Objects.requireNonNull(BY_TYPE.get(type));
		}

		public final int type;

		private TraceCommentChangeType(int type) {
			this.type = type;
			BY_TYPE.put(type, this);
		}
	}

	public static final class TraceCompositeDataChangeType<T, U>
			extends DefaultTraceChangeType<T, U> {
		public static final TraceCompositeDataChangeType<TraceAddressSnapRange, TraceData> ADDED =
			new TraceCompositeDataChangeType<>();
		public static final TraceCompositeDataChangeType<TraceData, Range<Long>> LIFESPAN_CHANGED =
			new TraceCompositeDataChangeType<>();
		public static final TraceCompositeDataChangeType<TraceAddressSnapRange, TraceData> REMOVED =
			new TraceCompositeDataChangeType<>();
	}

	public static final class TraceDataTypeChangeType<U> extends DefaultTraceChangeType<Long, U> {
		public static final TraceDataTypeChangeType<DataType> ADDED =
			new TraceDataTypeChangeType<>();
		// Old is null
		public static final TraceDataTypeChangeType<DataType> CHANGED =
			new TraceDataTypeChangeType<>();
		public static final TraceDataTypeChangeType<DataTypePath> REPLACED =
			new TraceDataTypeChangeType<>();
		public static final TraceDataTypeChangeType<DataTypePath> MOVED =
			new TraceDataTypeChangeType<>();
		public static final TraceDataTypeChangeType<String> RENAMED =
			new TraceDataTypeChangeType<>();
		public static final TraceDataTypeChangeType<DataTypePath> DELETED =
			new TraceDataTypeChangeType<>();
	}

	public static final class TraceFunctionChangeType<U>
			extends DefaultTraceChangeType<TraceFunctionSymbol, U> {
		// NOTE: ADDED/DELETED/LIFESPAN_CHANGED are SymbolChangeTypes
		public static final TraceFunctionChangeType<Void> CHANGED = new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<Integer> CHANGED_PURGE =
			new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<Boolean> CHANGED_INLINE =
			new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<Boolean> CHANGED_NORETURN =
			new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<String> CHANGED_CALL_FIXUP =
			new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<Void> CHANGED_RETURN =
			new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<Void> CHANGED_PARAMETERS =
			new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<TraceFunctionSymbol> CHANGED_THUNK =
			new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<AddressSetView> CHANGED_BODY =
			new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<FunctionTag> TAG_APPLIED =
			new TraceFunctionChangeType<>();
		public static final TraceFunctionChangeType<FunctionTag> TAG_REMOVED =
			new TraceFunctionChangeType<>();
		// TODO: VARIABLE_REFERENCE_ADDED? Or would these be reported by ref manager?
		// TODO: VARIABLE_REFERENCE_DELETED? Or would these be reported by ref manager?
	}

	public static final class TraceFunctionTagChangeType<U>
			extends DefaultTraceChangeType<FunctionTag, U> {
		public static final TraceFunctionTagChangeType<Void> ADDED =
			new TraceFunctionTagChangeType<>();
		public static final TraceFunctionTagChangeType<Void> CHANGED =
			new TraceFunctionTagChangeType<>();
		public static final TraceFunctionTagChangeType<Void> DELETED =
			new TraceFunctionTagChangeType<>();
	}

	public static final class TraceInstructionChangeType<U>
			extends DefaultTraceChangeType<TraceInstruction, U> {
		public static final TraceInstructionChangeType<FlowOverride> FLOW_OVERRIDE_CHANGED =
			new TraceInstructionChangeType<>();
		public static final TraceInstructionChangeType<Boolean> FALL_THROUGH_OVERRIDE_CHANGED =
			new TraceInstructionChangeType<>();
	}

	public static final class TraceMemoryBytesChangeType
			extends DefaultTraceChangeType<TraceAddressSnapRange, byte[]> {
		// byte array may be larger than actual change
		public static final TraceMemoryBytesChangeType CHANGED = new TraceMemoryBytesChangeType();
	}

	public static final class TraceMemoryRegionChangeType<U>
			extends DefaultTraceChangeType<TraceMemoryRegion, U> {
		public static final TraceMemoryRegionChangeType<Void> ADDED =
			new TraceMemoryRegionChangeType<>();
		public static final TraceMemoryRegionChangeType<Void> CHANGED =
			new TraceMemoryRegionChangeType<>();
		public static final TraceMemoryRegionChangeType<Range<Long>> LIFESPAN_CHANGED =
			new TraceMemoryRegionChangeType<>();
		public static final TraceMemoryRegionChangeType<Void> DELETED =
			new TraceMemoryRegionChangeType<>();
		// NOTE: No MOVING, SPLITTING, or JOINING
	}

	public static final class TraceMemoryStateChangeType<U>
			extends DefaultTraceChangeType<TraceAddressSnapRange, U> {
		public static final TraceMemoryStateChangeType<TraceMemoryState> CHANGED =
			new TraceMemoryStateChangeType<>();
	}

	public static final class TraceModuleChangeType<U>
			extends DefaultTraceChangeType<TraceModule, U> {
		public static final TraceModuleChangeType<Void> ADDED = new TraceModuleChangeType<>();
		public static final TraceModuleChangeType<Void> CHANGED = new TraceModuleChangeType<>();
		public static final TraceModuleChangeType<Range<Long>> LIFESPAN_CHANGED =
			new TraceModuleChangeType<>();
		// NOTE: module's sections will have been deleted, without events
		public static final TraceModuleChangeType<Void> DELETED = new TraceModuleChangeType<>();
	}

	public static final class TraceReferenceChangeType<T, U> extends DefaultTraceChangeType<T, U> {
		public static final TraceReferenceChangeType<TraceAddressSnapRange, TraceReference> ADDED =
			new TraceReferenceChangeType<>();
		public static final TraceReferenceChangeType<TraceReference, Range<Long>> LIFESPAN_CHANGED =
			new TraceReferenceChangeType<>();
		public static final TraceReferenceChangeType<TraceReference, Boolean> PRIMARY_CHANGED =
			new TraceReferenceChangeType<>();
		public static final TraceReferenceChangeType<TraceAddressSnapRange, TraceReference> DELETED =
			new TraceReferenceChangeType<>();
	}

	public static final class TraceSectionChangeType<U>
			extends DefaultTraceChangeType<TraceSection, U> {
		public static final TraceSectionChangeType<Void> ADDED = new TraceSectionChangeType<>();
		public static final TraceSectionChangeType<Void> CHANGED = new TraceSectionChangeType<>();
		public static final TraceSectionChangeType<Void> DELETED = new TraceSectionChangeType<>();
	}

	public static final class TraceStackChangeType<U>
			extends DefaultTraceChangeType<TraceStack, U> {
		public static final TraceStackChangeType<Void> ADDED = new TraceStackChangeType<>();
		public static final TraceStackChangeType<Void> CHANGED = new TraceStackChangeType<>();
		public static final TraceStackChangeType<Void> DELETED = new TraceStackChangeType<>();
	}

	public static final class TraceStaticMappingChangeType<U>
			extends DefaultTraceChangeType<TraceStaticMapping, U> {
		public static final TraceStaticMappingChangeType<Void> ADDED =
			new TraceStaticMappingChangeType<>();
		public static final TraceStaticMappingChangeType<Void> DELETED =
			new TraceStaticMappingChangeType<>();
	}

	public static final class TraceSourceArchiveChangeType<U>
			extends DefaultTraceChangeType<UniversalID, U> {
		public static final TraceSourceArchiveChangeType<Void> ADDED =
			new TraceSourceArchiveChangeType<>();
		public static final TraceSourceArchiveChangeType<Void> CHANGED =
			new TraceSourceArchiveChangeType<>();
		// TODO: Unused???
		public static final TraceSourceArchiveChangeType<Void> DELETED =
			new TraceSourceArchiveChangeType<>();
	}

	public static final class TraceSymbolChangeType<U>
			extends DefaultTraceChangeType<TraceSymbol, U> {
		public static final TraceSymbolChangeType<Void> ADDED = new TraceSymbolChangeType<>();
		public static final TraceSymbolChangeType<SourceType> SOURCE_CHANGED =
			new TraceSymbolChangeType<>();
		public static final TraceSymbolChangeType<TraceSymbol> SET_AS_PRIMARY =
			new TraceSymbolChangeType<>();
		public static final TraceSymbolChangeType<String> RENAMED = new TraceSymbolChangeType<>();
		public static final TraceSymbolChangeType<TraceNamespaceSymbol> PARENT_CHANGED =
			new TraceSymbolChangeType<>();
		public static final TraceSymbolChangeType<TraceReference> ASSOCIATION_ADDED =
			new TraceSymbolChangeType<>();
		public static final TraceSymbolChangeType<TraceReference> ASSOCIATION_REMOVED =
			new TraceSymbolChangeType<>();
		public static final TraceSymbolChangeType<Address> ADDRESS_CHANGED =
			new TraceSymbolChangeType<>();
		public static final DefaultTraceChangeType<TraceSymbolWithLifespan, Range<Long>> LIFESPAN_CHANGED =
			new DefaultTraceChangeType<>();
		public static final TraceSymbolChangeType<Void> DELETED = new TraceSymbolChangeType<>();
		// Other changes not captured above
		public static final TraceSymbolChangeType<Void> CHANGED = new TraceSymbolChangeType<>();
	}

	public static final class TraceThreadChangeType<U>
			extends DefaultTraceChangeType<TraceThread, U> {
		public static final TraceThreadChangeType<Void> ADDED = new TraceThreadChangeType<>();
		public static final TraceThreadChangeType<Void> CHANGED = new TraceThreadChangeType<>();
		public static final TraceThreadChangeType<Range<Long>> LIFESPAN_CHANGED =
			new TraceThreadChangeType<>();
		public static final TraceThreadChangeType<Void> DELETED = new TraceThreadChangeType<>();
	}

	public static final class TraceSnapshotChangeType<U>
			extends DefaultTraceChangeType<TraceSnapshot, U> {
		public static final TraceSnapshotChangeType<Void> ADDED = new TraceSnapshotChangeType<>();
		public static final TraceSnapshotChangeType<Void> CHANGED = new TraceSnapshotChangeType<>();
		public static final TraceSnapshotChangeType<Void> DELETED = new TraceSnapshotChangeType<>();
	}

	Language getBaseLanguage();

	CompilerSpec getBaseCompilerSpec();

	AddressFactory getBaseAddressFactory();

	TraceBookmarkManager getBookmarkManager();

	TraceBreakpointManager getBreakpointManager();

	TraceCodeManager getCodeManager();

	@Override
	TraceBasedDataTypeManager getDataTypeManager();

	TraceEquateManager getEquateManager();

	TraceLanguageManager getLanguageManager();

	TraceMemoryManager getMemoryManager();

	TraceModuleManager getModuleManager();

	TraceReferenceManager getReferenceManager();

	TraceRegisterContextManager getRegisterContextManager();

	TraceStackManager getStackManager();

	TraceStaticMappingManager getStaticMappingManager();

	TraceSymbolManager getSymbolManager();

	TraceThreadManager getThreadManager();

	TraceTimeManager getTimeManager();

	TraceProgramView getFixedProgramView(long snap);

	TraceVariableSnapProgramView createProgramView(long snap);

	/**
	 * Get the "canonical" program view for this trace
	 * 
	 * <p>
	 * This view is the view returned, e.g., by {@link TraceCodeUnit#getProgram()}, no matter which
	 * view was actually used to retrieve that unit.
	 * 
	 * @return the canonical program view
	 */
	TraceVariableSnapProgramView getProgramView();

	LockHold lockRead();

	LockHold lockWrite();
}
