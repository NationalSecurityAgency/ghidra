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

import java.util.Collection;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.lifecycle.Transitional;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataTypeManagerDomainObject;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.bookmark.TraceBookmarkManager;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointManager;
import ghidra.trace.model.context.TraceRegisterContextManager;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.trace.model.guest.TracePlatformManager;
import ghidra.trace.model.listing.TraceCodeManager;
import ghidra.trace.model.listing.TraceCodeUnit;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.trace.model.property.TraceAddressPropertyManager;
import ghidra.trace.model.stack.TraceStackManager;
import ghidra.trace.model.symbol.*;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.LockHold;

/**
 * An indexed record of observations over the course of a target's execution
 * 
 * <p>
 * Conceptually, this is the same as a {@link Program}, but multiplied by a concrete dimension of
 * time and organized into {@link TraceSnapshot snapshots}. This also includes information about
 * other objects not ordinarily of concern for static analysis, for example, {@link TraceThread
 * threads}, {@link TraceModule modules}, and {@link TraceBreakpoint breakpoints}. To view a
 * specific snapshot and/or manipulate the trace as if it were a program, use
 * {@link #getProgramView()}.
 */
public interface Trace extends DataTypeManagerDomainObject {
	Icon TRACE_ICON = new GIcon("icon.content.handler.trace");

	/**
	 * TEMPORARY: An a/b switch while both table- (legacy) and object-mode traces are supported
	 * 
	 * @param trace the trace, or null
	 * @return true if the trace is non-null and has no root schema
	 */
	@Transitional
	public static boolean isLegacy(Trace trace) {
		return trace != null && trace.getObjectManager().getRootSchema() == null;
	}

	public interface TraceProgramViewListener {
		void viewCreated(TraceProgramView view);
	}

	Language getBaseLanguage();

	CompilerSpec getBaseCompilerSpec();

	void setEmulatorCacheVersion(long version);

	long getEmulatorCacheVersion();

	AddressFactory getBaseAddressFactory();

	TraceAddressPropertyManager getAddressPropertyManager();

	TraceBookmarkManager getBookmarkManager();

	TraceBreakpointManager getBreakpointManager();

	TraceCodeManager getCodeManager();

	@Override
	TraceBasedDataTypeManager getDataTypeManager();

	TraceEquateManager getEquateManager();

	TracePlatformManager getPlatformManager();

	TraceMemoryManager getMemoryManager();

	TraceModuleManager getModuleManager();

	TraceObjectManager getObjectManager();

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
	 * Collect all program views, fixed or variable, of this trace.
	 * 
	 * @return the current set of program views
	 */
	Collection<TraceProgramView> getAllProgramViews();

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

	TraceTimeViewport createTimeViewport();

	void addProgramViewListener(TraceProgramViewListener listener);

	void removeProgramViewListener(TraceProgramViewListener listener);

	LockHold lockRead();

	LockHold lockWrite();
}
