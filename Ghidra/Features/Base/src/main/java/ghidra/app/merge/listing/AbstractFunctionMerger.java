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
package ghidra.app.merge.listing;

import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.dialogs.ReadTextDialog;
import generic.stl.Pair;
import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DiffUtility;
import ghidra.program.util.ProgramMerge;
import ghidra.util.*;
import ghidra.util.datastruct.ObjectIntHashtable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Abstract class that other function mergers can extend to get basic constants and methods 
 * for merging function changes. 
 * <br>Important: This class is intended to be used only for a single program 
 * version merge.
 */
abstract class AbstractFunctionMerger implements ListingMergeConstants {

	static protected final int BODY_CONFLICT_START = 35;
	static protected final int BODY_CONFLICT_SIZE = 25;
	static protected final int FUNCTION_CONFLICT_START = 60;
	static protected final int FUNCTION_CONFLICT_SIZE = 25;
	static protected final int DETAILS_CONFLICT_START = 85;
	static protected final int DETAILS_CONFLICT_SIZE = 15;

	static protected final int FUNC_OVERLAP = 0x001;
	static protected final int FUNC_BODY = 0x002;
	static protected final int FUNC_REMOVE = 0x004;
	static protected final int FUNC_THUNK = 0x008;

	static protected final int FUNC_RETURN = 0x001; // return type/storage conflict
	static protected final int FUNC_RETURN_ADDRESS_OFFSET = 0x002;
// For now, we are not allowing you to set the parameter offset or local size outright.
//	static protected final int FUNC_PARAMETER_OFFSET = 0x004;
//	static protected final int FUNC_LOCAL_SIZE = 0x008;
	static protected final int FUNC_STACK_PURGE_SIZE = 0x010;
	static protected final int FUNC_NAME = 0x020;
	static protected final int FUNC_INLINE = 0x040;
	static protected final int FUNC_NO_RETURN = 0x080;
	static protected final int FUNC_CALLING_CONVENTION = 0x100;
//	static protected final int FUNC_CUSTOM_STORAGE = 0x200; // custom mode differs
	static protected final int FUNC_VAR_STORAGE = 0x400; // overlapping variable storage 
	static protected final int FUNC_SIGNATURE = 0x800;
	static protected final int FUNC_LOCAL_DETAILS = 0x1000; // one or more local details differ
	static protected final int FUNC_PARAM_DETAILS = 0x2000; // one or more param details differ
//	static protected final int FUNC_LOCAL_REMOVED = 0x4000; // deleted variable conflicts with changes
	static protected final int FUNC_SIGNATURE_SOURCE = 0x8000;

	// FUNC_DETAIL_MASK doesn't include the FUNC_SIGNATURE_SOURCE, since signature source conflicts 
	// will get merged by priority instead of a user prompt.
	// NOTE: Custom storage attribute should be handled as a side-affect of achieving desired storage
	// for return and parameters not as an independently managed attribute
	static protected final int FUNC_DETAIL_MASK = FUNC_RETURN_ADDRESS_OFFSET |
		FUNC_STACK_PURGE_SIZE | FUNC_NAME | FUNC_INLINE | FUNC_NO_RETURN | // FUNC_CUSTOM_STORAGE |
		FUNC_CALLING_CONVENTION;

//	static protected final int VAR_TYPE = 0x001;
	static protected final int VAR_NAME = 0x002;
	static protected final int VAR_DATATYPE = 0x004;
//	static protected final int VAR_LENGTH = 0x008;
	static protected final int VAR_COMMENT = 0x010;
//	static protected final int VAR_STORAGE = 0x020;
//	static protected final int VAR_ORDINAL = 0x040;
//	static protected final int VAR_FIRST_USE = 0x080;
//	static protected final int VAR_REGISTER = 0x100;
	static protected final int VAR_REMOVED = 0x200;

	protected static final int HEADER = -1;
	protected static final int RESULT = MergeConstants.RESULT;
	protected static final int LATEST = MergeConstants.LATEST;
	protected static final int MY = MergeConstants.MY;
	protected static final int ORIGINAL = MergeConstants.ORIGINAL;

	protected static final int ORIGINAL_VAR = 0;
	protected static final int LATEST_VAR = 1;
	protected static final int MY_VAR = 2;

	protected StringBuffer errorBuf;
	protected StringBuffer infoBuf;

	protected ProgramMultiUserMergeManager mergeManager;
	protected Program[] programs = new Program[4];
	protected FunctionManager[] functionManagers = new FunctionManager[4];

	protected ListingMergeManager listingMergeManager;

	protected AddressFactory resultAddressFactory;

	protected Map<Long, DataType> latestResolvedDts; // maps data type ID -> resolved Data type
	protected Map<Long, DataType> myResolvedDts; // maps data type ID -> resolved Data type
	protected Map<Long, DataType> origResolvedDts;

	// mergePanel is a panel for listing merge conflicts. 
	// listings in CENTER, conflictInfoPanel in NORTH, mergeConflicts in SOUTH.
	protected ListingMergePanel listingMergePanel;

	protected VerticalChoicesPanel verticalConflictPanel;
	protected VariousChoicesPanel variousConflictPanel;
	protected ScrollingListChoicesPanel scrollingListConflictPanel;
	protected ConflictPanel currentConflictPanel;
	protected TaskMonitor currentMonitor;

	protected int overlapChoice = ASK_USER;
	protected int bodyChoice = ASK_USER;
	protected int functionReturnChoice = ASK_USER;
	protected int removeChoice = ASK_USER;
	protected int detailsChoice = ASK_USER;
	protected int variableStorageChoice = ASK_USER;
	protected int parameterSignatureChoice = ASK_USER;
	protected int parameterInfoChoice = ASK_USER;
	protected int removedLocalVariableChoice = ASK_USER;
	protected int localVariableDetailChoice = ASK_USER;
	protected int thunkChoice = ASK_USER;

	// *******************************************************************************************
	// *** Note: The removeSet & localsRemoveSet contains function entry points from the 
	// ***       ORIGINAL program.
	// *******************************************************************************************
	// removeSet is where one changed function and other removed.
	AddressSet removeSet;

	// *******************************************************************************************
	// *** Note: All other conflict address sets (other than the remove set) contain entry point
	// ***       addresses from MY program.
	// *******************************************************************************************
	// funcConflicts: key = Address [entryPoint], value = int (bits for each function detail type)
	protected ObjectIntHashtable<Address> funcConflicts;
	// Entry point addresses for Function Detail conflicts
	protected AddressSet funcSet;

	public AbstractFunctionMerger(ProgramMultiUserMergeManager mergeManager, Program[] programs) {
		this.mergeManager = mergeManager;
		this.programs = programs;
		if (programs.length != 4) {
			throw new IllegalArgumentException("Invalid program array passed to constructor.");
		}

		init();
	}

	private void init() {
		errorBuf = new StringBuffer();
		infoBuf = new StringBuffer();

		for (int i = 0; i < programs.length; i++) {
			functionManagers[i] = programs[i].getFunctionManager();
		}

		resultAddressFactory = programs[RESULT].getAddressFactory();

		removeSet = new AddressSet();

		funcConflicts = new ObjectIntHashtable<>();
		funcSet = new AddressSet();
	}

	/**
	 * Given a program and the ID of a datatype from that program, this method returns the
	 * associated data type in the Result program.
	 * @param dtID the ID of the data type in the "fromProgram".
	 * @param fromProgram the program that contains the data type with the specified ID.
	 * @return the associated data type in the Result program.
	 */
	DataType getResultDataType(long dtID, Program fromProgram) {
		DataType dt = null;
		if (fromProgram == programs[MY]) {
			dt = myResolvedDts.get(dtID);
			if (dt == null) {
				dt = programs[RESULT].getDataTypeManager().getDataType(dtID);
			}
		}
		else if (fromProgram == programs[LATEST]) {
			dt = latestResolvedDts.get(dtID);
			if (dt == null) {
				dt = programs[RESULT].getDataTypeManager().getDataType(dtID);
			}
		}
		else if (fromProgram == programs[ORIGINAL]) {
			dt = origResolvedDts.get(dtID);
		}
		else if (fromProgram == programs[RESULT]) {
			dt = programs[RESULT].getDataTypeManager().getDataType(dtID);
		}
		if (dt == null) {
			dt = fromProgram.getDataTypeManager().getDataType(dtID);
		}
		return dt;
	}

	/**
	 * Saves information indicating there is a conflict that needs to be resolved for a
	 * particular part of a function as indicated by the type. 
	 * @param functions the matching set of functions from Result, Latest, My, and Original
	 * (Some may be null) which have the detailed type of conflict.
	 * @param functionConflictFlags function conflict flags to be set
	 * 	(FUNC_RETURN_TYPE, FUNC_RETURN_ADDRESS_OFFSET, FUNC_STACK_PURGE_SIZE, FUNC_NAME
	 * 	FUNC_INLINE, FUNC_NO_RETURN, FUNC_CALLING_CONVENTION, FUNC_VAR_STORAGE
	 * 	FUNC_CUSTOM_STORAGE, FUNC_VAR_DETAILS, FUNC_SIGNATURE)
	 */
	abstract protected void saveFunctionDetailConflict(Function[] functions,
			int functionConflictFlags);

	abstract protected String getInfoTitle();

	abstract protected String getErrorTitle();

	/**
	 * Determines whether or not the part of the function, indicated by the type value, is in
	 * conflict for the matching set of functions. If not, then the function change is auto merged.
	 * @param functions the matching set of functions from Result, Latest, My, and Original 
	 * (Some may be null.)
	 * @param type (FUNC_RETURN_TYPE, FUNC_RETURN_ADDRESS_OFFSET,
	 * FUNC_PARAMETER_OFFSET, FUNC_LOCAL_SIZE, FUNC_STACK_PURGE_SIZE, FUNC_NAME, FUNC_INLINE, 
	 * FUNC_NO_RETURN, FUNC_CALLING_CONVENTION)
	 * @param latestMyChanges bit mask indicating the types of differences between Latest and My function.
	 * @param originalLatestChanges bit mask indicating the types of differences between Original and Latest function.
	 * @param originalMyChanges bit mask indicating the types of differences between Original and My function.
	 * @param monitor the merge status monitor for cancelling the merge and for reporting status.
	 * @return 0 if there isn't a conflict. Otherwise, if that type of conflict exists then 
	 * the type is returned.
	 */
	int determineFunctionConflict(Function[] functions, int type, int latestMyChanges,
			int originalLatestChanges, int originalMyChanges, TaskMonitor monitor) {
		if (((latestMyChanges & type) != 0) && ((originalMyChanges & type) != 0)) {
			// Mine changed function type
			if ((originalLatestChanges & type) != 0) {
				// Latest Changed function type
				StackFrame latestStack = functions[LATEST].getStackFrame();
				StackFrame myStack = functions[MY].getStackFrame();

				// See if both changed to same value.
				switch (type) {
					case FUNC_RETURN_ADDRESS_OFFSET:
						return (latestStack.getReturnAddressOffset() == myStack
								.getReturnAddressOffset())
										? 0
										: type;
// For now, we are not allowing you to set the parameter offset or local size outright.
//					case FUNC_PARAMETER_OFFSET:
//						return (latestStack.getParameterOffset() == myStack.getParameterOffset()) ? 0
//								: type;
//					case FUNC_LOCAL_SIZE:
//						return (latestStack.getLocalSize() == myStack.getLocalSize()) ? 0 : type;
					case FUNC_STACK_PURGE_SIZE:
						return (functions[LATEST].getStackPurgeSize() == functions[MY]
								.getStackPurgeSize())
										? 0
										: type;
					case FUNC_NAME:
						return hasUnresolvedFunctionNameConflict(functions, monitor) ? type : 0;
					case FUNC_INLINE:
						return (functions[LATEST].isInline() == functions[MY].isInline()) ? 0
								: type;
					case FUNC_NO_RETURN:
						return (functions[LATEST].hasNoReturn() == functions[MY].hasNoReturn()) ? 0
								: type;
//					case FUNC_CUSTOM_STORAGE:
//						return (functions[LATEST].hasCustomVariableStorage() == functions[MY].hasCustomVariableStorage()) ? 0
//								: type;
					case FUNC_CALLING_CONVENTION:
						return (functions[LATEST].getCallingConventionName()
								.equals(
									functions[MY].getCallingConventionName())) ? 0 : type;
					case FUNC_SIGNATURE_SOURCE:
						return (functions[LATEST].getSignatureSource() == functions[MY]
								.getSignatureSource())
										? 0
										: type;
					default:
						throw new IllegalArgumentException("type = " + type);
				}
			}
			// AutoMerge
			Address myEntryPoint = functions[MY].getEntryPoint();
			mergeFunctionDetail(type, myEntryPoint, getMergeMy(), monitor);
		}
		return 0; // No conflict
	}

	/**
	 * Process any dynamic name conflict and determine if there is any direct name conflict.
	 * Note: This method eliminates any conflict between a defined function name and 
	 * a dynamic, FUN_..., function name.
	 * @param functions the matching set of functions from Result, Latest, My, and Original.
	 * @param monitor the merge status monitor
	 * @return true if there is still a name conflict after this method is called.
	 */
	private boolean hasUnresolvedFunctionNameConflict(Function[] functions, TaskMonitor monitor) {
		String originalName = (functions[ORIGINAL] != null) ? functions[ORIGINAL].getName() : "";
		String latestName = (functions[LATEST] != null) ? functions[LATEST].getName() : "";
		String myName = (functions[MY] != null) ? functions[MY].getName() : "";
		boolean originalIsDefault = isDefaultName(functions[ORIGINAL]);
		boolean latestIsDefault = isDefaultName(functions[LATEST]);
		boolean myIsDefault = isDefaultName(functions[MY]);
		boolean latestAndMyAreSame = latestName.equals(myName) || (latestIsDefault && myIsDefault);
		boolean originalAndLatestAreSame =
			originalName.equals(latestName) || (originalIsDefault && latestIsDefault);
		boolean originalAndMyAreSame =
			originalName.equals(myName) || (originalIsDefault && myIsDefault);
		if (latestAndMyAreSame) {
			return false; // LATEST & MY are same. RESULT is already LATEST so leave alone.
		}
		if (originalAndMyAreSame) {
			return false; // Want LATEST. RESULT is already LATEST so leave alone.
		}
		if (originalAndLatestAreSame) {
			// Want MY.
			Address myEntryPoint = functions[MY].getEntryPoint();
			mergeFunctionDetail(FUNC_NAME, myEntryPoint, getMergeMy(), monitor);
			return false;
		}
		// Otherwise both changed the name. If LATEST or MY is a default then keep the other name.
		if (latestIsDefault) {
			// Keep MY.
			Address myEntryPoint = functions[MY].getEntryPoint();
			mergeFunctionDetail(FUNC_NAME, myEntryPoint, getMergeMy(), monitor);
			return false;
		}
		if (myIsDefault) {
			// Keep LATEST.
			return false;
		}
		return true; // LATEST & MY aren't defaults and were changed, so they conflict.
	}

	private boolean isDefaultName(Function function) {
		if (function != null) {
			String name = function.getName();
			Symbol symbol = function.getSymbol();
			SourceType source = symbol.getSource();
			boolean sourceIsDefault = (source == SourceType.DEFAULT);
			String defaultFunctionName =
				SymbolUtilities.getDefaultFunctionName(function.getEntryPoint());
			boolean matchesDefaultName = name.equals(defaultFunctionName);
			return sourceIsDefault || matchesDefaultName;
		}
		return false;
	}

	/**
	 * ProgramMerge that is used to merge from the Latest program into the ResultProgram
	 * @return the ProgramMerge for the Latest program.
	 */
	abstract ProgramMerge getMergeLatest();

	/**
	 * ProgramMerge that is used to merge from the My program into the ResultProgram
	 * @return the ProgramMerge for the My program.
	 */
	abstract ProgramMerge getMergeMy();

	/**
	 * ProgramMerge that is used to merge from the Original program into the ResultProgram
	 * @return the ProgramMerge for the Original program.
	 */
	abstract ProgramMerge getMergeOriginal();

	/**
	 * Compares the functions (Latest, Original, My) to determine where conflicting changes
	 * have been made to Latest and My. It then saves the conflict info within the merger for 
	 * later resolution and processing.
	 * @param functions the matching set of functions from Result, Latest, My, and Original.
	 * (Use MergeConstants.RESULT, LATEST, MY, ORIGINAL to reference these.)
	 * @param ignoreNames true indicates that function name differences should not be detected.
	 * @param monitor the merge status monitor
	 * @throws CancelledException if merge has been cancelled.
	 */
	void determineFunctionConflicts(Function[] functions, boolean ignoreNames, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCanceled();
		boolean isExternalFunction = (functions[LATEST] != null) ? functions[LATEST].isExternal()
				: ((functions[MY] != null) ? functions[MY].isExternal()
						: functions[ORIGINAL].isExternal());

		int functionConflictFlags = 0;

		int latestMyChanges = getFunctionDiffs(functions[LATEST], functions[MY]);
		if (latestMyChanges != 0) {

			int originalLatestChanges = getFunctionDiffs(functions[ORIGINAL], functions[LATEST]);
			int originalMyChanges = getFunctionDiffs(functions[ORIGINAL], functions[MY]);

//					functionConflictFlags |=
//						determineFunctionConflict(functions, FUNC_RETURN_TYPE, latestMyChanges,
//							originalLatestChanges, originalMyChanges, monitor);
			functionConflictFlags |=
				determineFunctionConflict(functions, FUNC_RETURN_ADDRESS_OFFSET, latestMyChanges,
					originalLatestChanges, originalMyChanges, monitor);

			// For now, we are not allowing you to set the parameter offset or local size outright.
			//		functionConflictFlags |=
			//			determineFunctionConflict(entry, FUNC_PARAMETER_OFFSET, latestMyChanges,
			//				originalLatestChanges, originalMyChanges, monitor);
			//		functionConflictFlags |=
			//			determineFunctionConflict(entry, FUNC_LOCAL_SIZE, latestMyChanges,
			//				originalLatestChanges, originalMyChanges, monitor);
			functionConflictFlags |= determineFunctionConflict(functions, FUNC_STACK_PURGE_SIZE,
				latestMyChanges, originalLatestChanges, originalMyChanges, monitor);
			if (!ignoreNames) {
				functionConflictFlags |= determineFunctionConflict(functions, FUNC_NAME,
					latestMyChanges, originalLatestChanges, originalMyChanges, monitor);
			}
			functionConflictFlags |= determineFunctionConflict(functions, FUNC_INLINE,
				latestMyChanges, originalLatestChanges, originalMyChanges, monitor);
			functionConflictFlags |= determineFunctionConflict(functions, FUNC_NO_RETURN,
				latestMyChanges, originalLatestChanges, originalMyChanges, monitor);

			// If FUNC_CALLING_CONVENTION conflict we must delay checking any storage related conflicts
			functionConflictFlags |= determineFunctionConflict(functions, FUNC_CALLING_CONVENTION,
				latestMyChanges, originalLatestChanges, originalMyChanges, monitor);
			functionConflictFlags |= determineFunctionConflict(functions, FUNC_SIGNATURE_SOURCE,
				latestMyChanges, originalLatestChanges, originalMyChanges, monitor);
		}

		// If the calling-convention is in conflict we must defer any specific storage and variable checking
		if ((functionConflictFlags & (FUNC_CALLING_CONVENTION)) == 0) {

			FunctionVariableStorageConflicts variableStorageConflicts = null;
			boolean skipParamChecks = false;
			if (!isExternalFunction) {
				variableStorageConflicts = determineStorageConflict(functions, monitor);
				skipParamChecks = variableStorageConflicts != null &&
					variableStorageConflicts.hasParameterConflict();
			}

			if (!skipParamChecks && determineSignatureConflicts(functions, monitor)) {
				determineParameterInfoConflicts(functions, true, monitor);
			}

			determineReturnConflict(functions, true, monitor);

			if (!isExternalFunction) {
				determineLocalVariableInfoConflicts(functions, true, variableStorageConflicts,
					monitor);
			}
		}

		if (functionConflictFlags != 0) {
			saveFunctionDetailConflict(functions, functionConflictFlags);
		}
	}

	protected FunctionVariableStorageConflicts determineStorageConflict(Function[] functions,
			TaskMonitor monitor) throws CancelledException {
		if (functions[LATEST] == null || functions[MY] == null) {
			return null;
		}
		FunctionVariableStorageConflicts variableStorageConflicts =
			new FunctionVariableStorageConflicts(functions[LATEST], functions[MY],
				!functions[RESULT].hasCustomVariableStorage(), monitor);
		if (!variableStorageConflicts.hasOverlapConflict()) {
			return null;
		}
		saveFunctionDetailConflict(functions, FUNC_VAR_STORAGE);
		return variableStorageConflicts;
	}

	/**
	 * Compares the functions (Latest, Original, My) to determine if a parameter signature 
	 * conflict exists and auto-merges any signature change if possible, otherwise 
	 * the {@link #FUNC_SIGNATURE} conflict flag may be set for the current function
	 * signaling the merger for later resolution and processing.
	 * @param functions the matching set of functions from Result, Latest, My, and Original.
	 * @param monitor the merge status monitor
	 * @return true if signatures match and a check should be performed for parameter detail 
	 * conflicts, otherwise false is returned and the {@link #FUNC_SIGNATURE} conflict flag
	 * may be set for the current function
	 * @throws CancelledException if merge has been cancelled.
	 */
	boolean determineSignatureConflicts(Function[] functions, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCanceled();
		Address entry = (functions[LATEST] != null) ? functions[LATEST].getEntryPoint()
				: ((functions[MY] != null) ? functions[MY].getEntryPoint()
						: functions[ORIGINAL].getEntryPoint());
		boolean latestChangedParamSig = !isSameParamSig(functions[ORIGINAL], functions[LATEST]);
		boolean myChangedParamSig = !isSameParamSig(functions[ORIGINAL], functions[MY]);
		boolean latestChangedParamInfo = !isSameParamInfo(functions[ORIGINAL], functions[LATEST]);
		boolean myChangedParamInfo = !isSameParamInfo(functions[ORIGINAL], functions[MY]);
		boolean latestChangedReturn = functionReturnDiffers(functions[ORIGINAL], functions[LATEST]);
		boolean myChangedReturn = functionReturnDiffers(functions[ORIGINAL], functions[MY]);
		boolean sameSig = isSameParamSig(functions[LATEST], functions[MY]);
		if (sameSig) {
			if (myChangedParamInfo || myChangedReturn) {
				if (latestChangedParamInfo || latestChangedReturn) {
					return true;
				}
				// Auto-merge my parameter and return changes.
				getMergeMy().replaceFunctionParameters(entry, monitor);
			}
			// ELSE only the latest could have changed param info & we have those changes.
		}
		else if (latestChangedParamSig) {
			if (myChangedParamSig || myChangedParamInfo || myChangedReturn) {
				saveFunctionDetailConflict(functions, FUNC_SIGNATURE);
			}
			// ELSE Only latest parameter signature changed so already has new signature.
		}
		else if (myChangedParamSig) {
			if (latestChangedParamInfo || latestChangedReturn) {
				saveFunctionDetailConflict(functions, FUNC_SIGNATURE);
			}
			else {
				// Only my parameter signature changed so autoMerge my parameters.
				getMergeMy().replaceFunctionParameters(entry, monitor);
			}
		}
		return false;
	}

	private boolean functionReturnDiffers(Function func1, Function func2) {
		if (func1 == null && func2 == null) {
			return false;
		}
		if (func1 == null || func2 == null) {
			return true;
		}
		return !func1.getReturn().equals(func2.getReturn());
	}

	protected boolean determineReturnConflict(Function[] functions, boolean autoMerge,
			TaskMonitor monitor) {
		Address entry = (functions[LATEST] != null) ? functions[LATEST].getEntryPoint()
				: ((functions[MY] != null) ? functions[MY].getEntryPoint()
						: functions[ORIGINAL].getEntryPoint());

		try {
			int conflicts = funcConflicts.get(entry);
			if ((conflicts & FUNC_SIGNATURE) != 0) {
				return false; // skip check if signature difference already detected
			}
		}
		catch (NoValueException e) {
			// ignore
		}

		boolean latestMyDiffers = functionReturnDiffers(functions[LATEST], functions[MY]);
		if (!latestMyDiffers) {
			return false;
		}
		boolean originalLatestDiffers =
			functionReturnDiffers(functions[ORIGINAL], functions[LATEST]);
		boolean originalMyDiffers = functionReturnDiffers(functions[ORIGINAL], functions[MY]);

		if (latestMyDiffers && originalMyDiffers) {
			if (originalLatestDiffers) {

				Parameter latestReturn = functions[LATEST].getReturn();
				Parameter myReturn = functions[MY].getReturn();

				boolean storageDiffers = false;

				// RESULT is checked for custom storage state since this must be resolved
				// prior to invoking this method - no need to check storage if custom
				// storage is not used
				if (functions[RESULT].hasCustomVariableStorage()) {
					storageDiffers =
						!latestReturn.getVariableStorage().equals(myReturn.getVariableStorage());
				}
				if (!storageDiffers) {
					long latestID =
						programs[LATEST].getDataTypeManager().getID(latestReturn.getDataType());
					long myID = programs[MY].getDataTypeManager().getID(myReturn.getDataType());
					DataType latestResultDt = getResultDataType(latestID, programs[LATEST]);
					DataType myResultDt = getResultDataType(myID, programs[MY]);
					if (latestResultDt == myResultDt) {
						return false;
					}
				}
				saveFunctionDetailConflict(functions, FUNC_RETURN);
				return true;
			}
			else if (autoMerge) {
				getMergeMy().mergeFunctionReturn(entry);
			}
		}
		return false;
	}

	protected List<ParamInfoConflict> determineParameterInfoConflicts(Function[] functions,
			boolean autoMerge, TaskMonitor monitor) {
		ArrayList<ParamInfoConflict> paramConflictList = null;
		Address entry = (functions[LATEST] != null) ? functions[LATEST].getEntryPoint()
				: ((functions[MY] != null) ? functions[MY].getEntryPoint()
						: functions[ORIGINAL].getEntryPoint());

		// TODO: How should we deal with auto-params which are immutable ??
		// assume we are only here is LATEST and MY have "same" sig/storage which for 
		// dynamic storage means same number of non-auto params

		Parameter[] origParms =
			(functions[ORIGINAL] != null) ? functions[ORIGINAL].getParameters() : new Parameter[0];
		Parameter[] latestParms =
			(functions[LATEST] != null) ? functions[LATEST].getParameters() : new Parameter[0];
		Parameter[] myParms =
			(functions[MY] != null) ? functions[MY].getParameters() : new Parameter[0];

		int numParms = myParms.length;
		for (int ordinal = 0; ordinal < numParms; ordinal++) {
			Parameter originalParameter = (ordinal < origParms.length) ? origParms[ordinal] : null;
			Parameter latestParameter =
				(ordinal < latestParms.length) ? latestParms[ordinal] : null;
			if (latestParameter != null && latestParameter.isAutoParameter()) {
				continue; // can't mutate auto-param
			}
			Parameter myParameter = (ordinal < myParms.length) ? myParms[ordinal] : null;
			int latestMyChanges = getVariableDiffs(latestParameter, myParameter);
			if (latestMyChanges == 0) {
				continue;
			}
			int originalLatestChanges = getVariableDiffs(originalParameter, latestParameter);
			int originalMyChanges = getVariableDiffs(originalParameter, myParameter);
			int paramConflicts = 0;
//			paramConflicts |=
//				determineVariableConflict(entry, VAR_TYPE, myParameter, latestMyChanges,
//					originalLatestChanges, originalMyChanges, monitor);
			if (paramConflicts == 0) {
				paramConflicts |= determineVariableConflict(entry, VAR_NAME, myParameter,
					latestMyChanges, originalLatestChanges, originalMyChanges, autoMerge, monitor);
				paramConflicts |= determineVariableConflict(entry, VAR_DATATYPE, myParameter,
					latestMyChanges, originalLatestChanges, originalMyChanges, autoMerge, monitor);
//				paramConflicts |= determineVariableConflict(entry, VAR_LENGTH,    myP, latestMyChanges, 
//															originalLatestChanges, originalMyChanges, monitor);
				paramConflicts |= determineVariableConflict(entry, VAR_COMMENT, myParameter,
					latestMyChanges, originalLatestChanges, originalMyChanges, autoMerge, monitor);
//				paramConflicts |=
//					determineVariableConflict(entry, VAR_STORAGE, myParameter, latestMyChanges,
//						originalLatestChanges, originalMyChanges, autoMerge, monitor);
//				paramConflicts |= determineVariableConflict(entry, VAR_FIRST_USE, myP, latestMyChanges, 
//															originalLatestChanges, originalMyChanges, monitor);
//				paramConflicts |= determineVariableConflict(entry, VAR_OFFSET,    myP, latestMyChanges, 
//															originalLatestChanges, originalMyChanges, monitor);
//				paramConflicts |= determineVariableConflict(entry, VAR_ORDINAL,   myP, latestMyChanges, 
//															originalLatestChanges, originalMyChanges, monitor);
//				paramConflicts |= determineVariableConflict(entry, VAR_REGISTER,  myP, latestMyChanges, 
//															originalLatestChanges, originalMyChanges, monitor);
			}
			if (paramConflicts != 0) {
				if (paramConflictList == null) {
					paramConflictList = new ArrayList<>();
				}
				paramConflictList.add(new ParamInfoConflict(entry, ordinal, paramConflicts));
			}
		}
		if (paramConflictList != null) {
			saveFunctionDetailConflict(functions, FUNC_PARAM_DETAILS);
		}
		return paramConflictList;
	}

	boolean isSameParamSig(Function f1, Function f2) { // only concerned with parameter count and param/return storage matchup
		if (f1 == null) {
			return (f2 == null);
		}
		else if (f2 == null) {
			return false;
		}
		if (f1.hasVarArgs() != f2.hasVarArgs()) {
			return false;
		}
		Parameter[] f1Parms = f1.getParameters();
		Parameter[] f2Parms = f2.getParameters();

		if (f1Parms.length != f2Parms.length) {
			return false;
		}

		// NOTE: Parameter level merging gets really complex when the presence of auto-params are inconsistent
		// between between two functions treat as a signature difference when this occurs

		for (int i = 0; i < f1Parms.length; i++) {
			if (f1Parms[i].isAutoParameter() != f2Parms[i].isAutoParameter() ||
				f1Parms[i].isForcedIndirect() != f2Parms[i].isForcedIndirect()) {
				return false;
			}
		}

		if (!f1.hasCustomVariableStorage() && !f2.hasCustomVariableStorage()) {
			return true; // don't care about specific storage
		}

		// Same param count with either f1 or f2 using custom storage - must compare the storage.

		Parameter return1 = f1.getReturn();
		Parameter return2 = f2.getReturn();
		if (return1.getLength() != return2.getLength() ||
			!return1.getVariableStorage().equals(return2.getVariableStorage())) {
			return false;
		}

		for (int i = 0; i < f1Parms.length; i++) {
			if (!f1Parms[i].getVariableStorage().equals(f2Parms[i].getVariableStorage())) {
				return false;
			}
		}
		return true;
	}

	private boolean isSameParamInfo(Function f1, Function f2) {
		if (f1 == null) {
			return (f2 == null);
		}
		else if (f2 == null) {
			return false;
		}

		Parameter[] f1Parms = f1.getParameters();
		Parameter[] f2Parms = f2.getParameters();

		if (f1.hasCustomVariableStorage() || f2.hasCustomVariableStorage()) {
			f1Parms = f1.getParameters();
			f2Parms = f2.getParameters();
		}
		else {
			// if both f1 and f2 use dynamic storage only consider non-auto params
			f1Parms = f1.getParameters(VariableFilter.NONAUTO_PARAMETER_FILTER);
			f2Parms = f2.getParameters(VariableFilter.NONAUTO_PARAMETER_FILTER);
		}

		if (f1Parms.length != f2Parms.length) {
			return false;
		}
		for (int i = 0; i < f1Parms.length; i++) {
			if (!f1Parms[i].isEquivalent(f2Parms[i])) {
				return false;
			}
			if (!StringUtils.equals(f1Parms[i].getName(), f2Parms[i].getName())) {
				return false;
			}
			if (!StringUtils.equals(f1Parms[i].getComment(), f2Parms[i].getComment())) {
				return false;
			}
		}
		return true;
	}

	private int determineVariableConflict(Address entry, int varType, Variable var,
			int latestMyChanges, int originalLatestChanges, int originalMyChanges,
			boolean autoMerge, TaskMonitor monitor) {
		if (((latestMyChanges & varType) != 0) && ((originalMyChanges & varType) != 0)) {
			// Mine changed variable type
			if ((originalLatestChanges & varType) != 0) {
				// Latest Changed variable type
				return varType;
			}
			// AutoMerge
			if (autoMerge) {
				mergeVariable(varType, entry, var, getMergeMy(), monitor);
			}
		}
		return 0;
	}

	class ParamInfoConflict {
		Address entry;
		int ordinal;
		int paramConflicts;

		ParamInfoConflict(Address entry, int ordinal, int paramConflicts) {
			this.entry = entry;
			this.ordinal = ordinal;
			this.paramConflicts = paramConflicts;
		}
	}

	class LocalVariableConflict {
		Address entry;
		Variable[] vars;
		int varConflicts;

		/**
		 * 
		 * @param entry
		 * @param vars an array of the 3 variables (Original, Latest, My) in conflict.
		 * @param varConflicts
		 */
		LocalVariableConflict(Address entry, Variable[] vars, int varConflicts) {
			this.entry = entry;
			this.vars = vars;
			this.varConflicts = varConflicts;
		}
	}

	private void mergeParameter(int type, Address entry, int ordinal, ProgramMerge pgmMerge,
			TaskMonitor monitor) {
		if (pgmMerge == null) {
			return;
		}
		switch (type) {
//			case VAR_TYPE:
//				pgmMerge.replaceFunctionParameter(entry, ordinal, monitor);
//				break;
			case VAR_NAME:
				try {
					pgmMerge.replaceFunctionParameterName(entry, ordinal, monitor);
				}
				catch (InvalidInputException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
				catch (DuplicateNameException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
				break;
			case VAR_DATATYPE:
				pgmMerge.replaceFunctionParameterDataType(entry, ordinal, monitor);
				break;
//			case VAR_LENGTH:
//        			pgmMerge.replaceFunctionVariableLength(entry, var, monitor);
//				break;
			case VAR_COMMENT:
				pgmMerge.replaceFunctionParameterComment(entry, ordinal, monitor);
				break;
//			case VAR_FIRST_USE:
//        			pgmMerge.replaceFunctionVariableFirstUse(entry, var, monitor);
//				break;
//			case VAR_OFFSET:
//        			pgmMerge.replaceFunctionVariableOffset(entry, var, monitor);
//				break;
//			case VAR_ORDINAL:
//        			pgmMerge.replaceFunctionParameterOrdinal(entry, var, monitor);
//				break;
//			case VAR_REGISTER:
//        			pgmMerge.replaceFunctionVariableRegister(entry, var, monitor);
//				break;
		}
	}

	protected void mergeParameter(int type, Address entry, int ordinal, int currentConflictOption,
			TaskMonitor monitor) {
		mergeParameter(type, entry, ordinal, getProgramListingMerge(currentConflictOption),
			monitor);
	}

	protected void mergeParameter(int type, Function[] functions, int ordinal,
			int currentConflictOption, TaskMonitor monitor) {
		ProgramMerge programMerge = null;
		Address entryPoint = null;
		if ((currentConflictOption & KEEP_ORIGINAL) != 0) {
			programMerge = getMergeOriginal();
			entryPoint = (functions[ORIGINAL] != null) ? functions[ORIGINAL].getEntryPoint() : null;
		}
		else if ((currentConflictOption & KEEP_LATEST) != 0) {
			programMerge = getMergeLatest();
			entryPoint = (functions[LATEST] != null) ? functions[LATEST].getEntryPoint() : null;
		}
		else if ((currentConflictOption & KEEP_MY) != 0) {
			programMerge = getMergeMy();
			entryPoint = (functions[MY] != null) ? functions[MY].getEntryPoint() : null;
		}
		else {
			throw new IllegalArgumentException(
				currentConflictOption + " is not a valid value for the currentConflictOption.");
		}
		mergeParameter(type, entryPoint, ordinal, programMerge, monitor);
	}

	void mergeLocalVariable(int type, Address entry, Variable[] vars, int currentConflictOption,
			TaskMonitor monitor) {

		Variable var = null;
		for (int i = 0; i < 3; i++) {
			if (vars[i] != null) {
				var = vars[i];
				break;
			}
		}
		mergeVariable(type, entry, var, getProgramListingMerge(currentConflictOption), monitor);
	}

	void mergeVariable(int type, Address entry, Variable var, ProgramMerge pgmMerge,
			TaskMonitor monitor) {

		if (pgmMerge == null) {
			return;
		}
		switch (type) {
			case VAR_REMOVED:
//			case VAR_TYPE:
				pgmMerge.replaceFunctionVariable(entry, var, monitor);
				break;
			case VAR_NAME:
				try {
					pgmMerge.replaceFunctionVariableName(entry, var, monitor);
				}
				catch (DuplicateNameException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
				catch (InvalidInputException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
				break;
			case VAR_DATATYPE:
				pgmMerge.replaceFunctionVariableDataType(entry, var, monitor);
				break;
//			case VAR_LENGTH:
//        			pgmMerge.replaceFunctionVariableLength(entry, var, monitor);
//				break;
			case VAR_COMMENT:
				pgmMerge.replaceFunctionVariableComment(entry, var, monitor);
				break;
//			case VAR_FIRST_USE:
//        			pgmMerge.replaceFunctionVariableFirstUse(entry, var, monitor);
//				break;
//			case VAR_OFFSET:
//        			pgmMerge.replaceFunctionVariableOffset(entry, var, monitor);
//				break;
//			case VAR_ORDINAL:
//        			pgmMerge.replaceFunctionParameterOrdinal(entry, var, monitor);
//				break;
//			case VAR_REGISTER:
//        			pgmMerge.replaceFunctionVariableRegister(entry, var, monitor);
//				break;
			default:
				throw new AssertException("Unsupported type: 0x" + Integer.toHexString(type));
		}
		if (!monitor.isCancelled()) {
			handleProgramMergeMessages(pgmMerge);
		}
	}

	/**
	 * Compares the two functions and determines where the function information 
	 * differs (name, return type, return address offset, parameter offset, 
	 * local size, stack purge size). Sets bits within the int value indicating 
	 * which info differs between the two functions.
	 * @param func1 the first function
	 * @param func2 the second function
	 * @return an int with bits set indicating where the two functions differ.
	 */
	static int getFunctionDiffs(Function func1, Function func2) {
		int diffs = 0;
		if (func1 == null && func2 == null) {
			return 0;
		}
		if (func1 == null || func2 == null) {
			return FUNC_DETAIL_MASK;
		}
		StackFrame stack1 = func1.getStackFrame();
		StackFrame stack2 = func2.getStackFrame();

		if (!SystemUtilities.isEqual(func1.getName(), func2.getName())) {
			diffs |= FUNC_NAME;
		}
//		if (!SystemUtilities.isEqual(func1.getReturnType(), func2.getReturnType())) {
//			diffs |= FUNC_RETURN_TYPE;
//		}
		if (stack1.getReturnAddressOffset() != stack2.getReturnAddressOffset()) {
			diffs |= FUNC_RETURN_ADDRESS_OFFSET;
		}
// For now, we are not allowing you to set the parameter offset or local size outright.
//		if (stack1.getParameterOffset() != stack2.getParameterOffset()) {
//			diffs |= FUNC_PARAMETER_OFFSET;
//		}
//		if (stack1.getLocalSize() != stack2.getLocalSize()) {
//			diffs |= FUNC_LOCAL_SIZE;
//		}
		if (func1.getStackPurgeSize() != func2.getStackPurgeSize()) {
			diffs |= FUNC_STACK_PURGE_SIZE;
		}
		if (func1.isInline() != func2.isInline()) {
			diffs |= FUNC_INLINE;
		}
		if (func1.hasNoReturn() != func2.hasNoReturn()) {
			diffs |= FUNC_NO_RETURN;
		}
		if (!func1.getCallingConventionName().equals(func2.getCallingConventionName())) {
			diffs |= FUNC_CALLING_CONVENTION;
		}
		if (func1.getSignatureSource() != func2.getSignatureSource()) {
			diffs |= FUNC_SIGNATURE_SOURCE;
		}
		return diffs;
	}

	/**
	 * Determines differences between two variables.
	 * @param var1 the first variable
	 * @param var2 the second variable
	 * @return an int with bits set indicating where the two variables differ.
	 */
	private int getVariableDiffs(Variable var1, Variable var2) {
		int diffs = 0;
		if (var1 == null && var2 == null) {
			return 0;
		}
		if (var1 == null || var2 == null) {
			return VAR_NAME | VAR_DATATYPE | VAR_COMMENT;
		}

//		VariableStorage storage1 = var1.getVariableStorage();
//		VariableStorage storage2 = var2.getVariableStorage();
//		if (!storage1.equals(storage2)) {
//			diffs |= VAR_STORAGE;
//		}

//		int ordinal1 = -1;
//		int ordinal2 = -1;
//		if (var1 instanceof Parameter) {
//			Parameter p1 = (Parameter) var1;
//			ordinal1 = p1.getOrdinal();
//		}
//		if (var2 instanceof Parameter) {
//			Parameter p2 = (Parameter) var2;
//			ordinal2 = p2.getOrdinal();
//		}
//		if (ordinal1 != ordinal2) {
//			diffs |= VAR_ORDINAL;
//		}
//
//		if (!var1.getClass().equals(var2.getClass())) {
//			diffs |= VAR_TYPE;
//		}
		if (!var1.getName().equals(var2.getName())) {
			diffs |= VAR_NAME;
		}
		if (!var1.getDataType().isEquivalent(var2.getDataType())) {
			diffs |= VAR_DATATYPE;
		}
//		if (var1.getLength() != var2.getLength()) {
//			diffs |= VAR_LENGTH;
//		}
		if (!SystemUtilities.isEqual(var1.getComment(), var2.getComment())) {
			diffs |= VAR_COMMENT;
		}
		return diffs;
	}

	// TODO: need to pass-in storage conflicts so conflicted variables can be skipped
	List<LocalVariableConflict> determineLocalVariableInfoConflicts(Function[] functions,
			boolean autoMerge, FunctionVariableStorageConflicts storageConflicts,
			TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		ArrayList<LocalVariableConflict> varConflictList = null;
		Address entry = (functions[LATEST] != null) ? functions[LATEST].getEntryPoint()
				: ((functions[MY] != null) ? functions[MY].getEntryPoint()
						: functions[ORIGINAL].getEntryPoint());
		Variable[] origLocals =
			(functions[ORIGINAL] != null) ? functions[ORIGINAL].getLocalVariables()
					: new Variable[0];
		Variable[] latestLocals =
			(functions[LATEST] != null) ? functions[LATEST].getLocalVariables() : new Variable[0];
		Variable[] myLocals =
			(functions[MY] != null) ? functions[MY].getLocalVariables() : new Variable[0];
		Arrays.sort(origLocals);
		Arrays.sort(latestLocals);
		Arrays.sort(myLocals);
		// Match up the variables by offset and firstUseOffset.
		MultiComparableArrayIterator<Variable> varIter = new MultiComparableArrayIterator<>(
			new Variable[][] { origLocals, latestLocals, myLocals });
		while (varIter.hasNext()) {
			Variable[] vars = varIter.next();
			Variable origVar = vars[ORIGINAL_VAR];
			Variable latestVar = vars[LATEST_VAR];
			Variable myVar = vars[MY_VAR];

			// if MultiComparableArrayIterator returns both latestVar and myVar their should be
			// no conflict since they must have the same storage to be matched-up
			if ((latestVar == null || myVar == null) && storageConflicts != null) {
				if (storageConflicts.isConflicted(latestVar, myVar)) {
					continue;
				}
			}

			int latestMyChanges = getVariableDiffs(latestVar, myVar);
			if (latestMyChanges == 0) {
				continue; // latest and my are same or both deleted 
			}

			boolean removedLatest = (origVar != null && latestVar == null);
			boolean removedMy = (origVar != null && myVar == null);
			int originalLatestChanges = getVariableDiffs(origVar, latestVar);
			int originalMyChanges = getVariableDiffs(origVar, myVar);
			int varConflicts = 0;

			if ((removedLatest && (originalMyChanges != 0)) ||
				(removedMy && (originalLatestChanges != 0))) {
				varConflicts |= VAR_REMOVED;
			}
			else if (removedMy) {
				if (autoMerge && !removedLatest) {
					// Auto merge variable removal 
					getMergeMy().replaceFunctionVariable(entry, origVar, monitor);
				}
				continue;
			}
			else if (origVar == null && myVar != null && latestVar == null) {
				if (autoMerge) {
					// Auto merge variable added to MY function
					getMergeMy().replaceFunctionVariable(entry, myVar, monitor);
				}
				continue;
			}
			else {

//			varConflicts |=
//				determineVariableConflict(entry, VAR_TYPE, myVar, latestMyChanges,
//					originalLatestChanges, originalMyChanges, monitor);
//			if (varConflicts == 0) {
				varConflicts |= determineVariableConflict(entry, VAR_NAME, myVar, latestMyChanges,
					originalLatestChanges, originalMyChanges, autoMerge, monitor);
				varConflicts |= determineVariableConflict(entry, VAR_DATATYPE, myVar,
					latestMyChanges, originalLatestChanges, originalMyChanges, autoMerge, monitor);
//			varConflicts |=
//				determineVariableConflict(entry, VAR_LENGTH, myVar, latestMyChanges,
//					originalLatestChanges, originalMyChanges, autoMerge, monitor);
				varConflicts |= determineVariableConflict(entry, VAR_COMMENT, myVar,
					latestMyChanges, originalLatestChanges, originalMyChanges, autoMerge, monitor);
//				varConflicts |=
//					determineVariableConflict(entry, VAR_FIRST_USE, myVar, latestMyChanges,
//						originalLatestChanges, originalMyChanges, monitor);
//			varConflicts |=
//				determineVariableConflict(entry, VAR_STORAGE, myVar, latestMyChanges,
//					originalLatestChanges, originalMyChanges, autoMerge, monitor);
//				varConflicts |=
//					determineVariableConflict(entry, VAR_ORDINAL, myVar, latestMyChanges,
//						originalLatestChanges, originalMyChanges, monitor);
//				varConflicts |=
//					determineVariableConflict(entry, VAR_REGISTER, myVar, latestMyChanges,
//						originalLatestChanges, originalMyChanges, monitor);
			}
			if (varConflicts != 0) {
				if (varConflictList == null) {
					varConflictList = new ArrayList<>();
				}
				varConflictList.add(new LocalVariableConflict(entry, vars, varConflicts));
			}
		}
		if (varConflictList != null) {
			saveFunctionDetailConflict(functions, FUNC_LOCAL_DETAILS);
		}
		return varConflictList;
	}

	class FunctionAddressIterator implements AddressIterator {
		FunctionIterator functionIterator;

		FunctionAddressIterator(FunctionIterator funcIter) {
			this.functionIterator = funcIter;
		}

		/* (non-Javadoc)
		 * @see ghidra.program.model.address.AddressIterator#next()
		 */
		@Override
		public Address next() {
			return (functionIterator.next()).getEntryPoint();
		}

		/* (non-Javadoc)
		 * @see ghidra.program.model.address.AddressIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			return functionIterator.hasNext();
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Address> iterator() {
			return this;
		}
	}

	protected int countSetBits(int bits) {
		int count = 0;
		for (int i = 0; i < 32; i++) {
			if ((bits & 0x1) != 0) {
				count++;
			}
			bits >>>= 1;
		}
		return count;
	}

	protected void mergeFunctionDetail(int type, Address entry, ProgramMerge pgmMerge,
			TaskMonitor monitor) {

		if (pgmMerge == null) {
			return;
		}
		switch (type) {
			case FUNC_NAME:
				pgmMerge.mergeFunctionName(entry, monitor);
				break;
//			case FUNC_RETURN_TYPE:
//				pgmMerge.mergeFunctionReturnType(entry, monitor);
//				break;
			case FUNC_RETURN_ADDRESS_OFFSET:
				pgmMerge.mergeFunctionReturnAddressOffset(entry, monitor);
				break;
// For now, we are not allowing you to set the parameter offset or local size outright.
//			case FUNC_PARAMETER_OFFSET:
//				pgmMerge.mergeFunctionParameterOffset(entry, monitor);
//				break;
//			case FUNC_LOCAL_SIZE:
//				pgmMerge.mergeFunctionLocalSize(entry, monitor);
//				break;
			case FUNC_STACK_PURGE_SIZE:
				pgmMerge.mergeFunctionStackPurgeSize(entry, monitor);
				break;
			case FUNC_INLINE:
				pgmMerge.replaceFunctionInlineFlag(entry, monitor);
				break;
			case FUNC_NO_RETURN:
				pgmMerge.replaceFunctionNoReturnFlag(entry, monitor);
				break;
			case FUNC_CALLING_CONVENTION:
				pgmMerge.replaceFunctionCallingConvention(entry, monitor);
				break;
			case FUNC_SIGNATURE_SOURCE:
				pgmMerge.replaceFunctionSignatureSource(entry, monitor);
				break;
			default:
				throw new IllegalArgumentException("type = " + type);
		}
	}

	private void mergeFunctionDetail(int type, Function[] functions, int chosenConflictOption,
			TaskMonitor monitor) {
		Address entryPoint = getEntryPoint(functions, chosenConflictOption);
		ProgramMerge programListingMerge = getProgramListingMerge(chosenConflictOption);
		mergeFunctionDetail(type, entryPoint, programListingMerge, monitor);
	}

	ProgramMerge getProgramListingMerge(int chosenConflictOption) {
		if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
			return getMergeOriginal();
		}
		else if ((chosenConflictOption & KEEP_LATEST) != 0) {
			return getMergeLatest();
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			return getMergeMy();
		}
		else {
			return null;
		}
	}

	Address getEntryPoint(Function[] functions, int chosenConflictOption) {
		Function function = null;
		if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
			function = functions[ORIGINAL];
		}
		else if ((chosenConflictOption & KEEP_LATEST) != 0) {
			function = functions[LATEST];
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			function = functions[MY];
		}
		else if ((chosenConflictOption & KEEP_RESULT) != 0) {
			function = functions[RESULT];
		}
		return (function != null) ? function.getEntryPoint() : null;
	}

	private void handleProgramMergeMessages(ProgramMerge pm) {

		errorBuf.append(pm.getErrorMessage());
		pm.clearErrorMessage();

		infoBuf.append(pm.getInfoMessage());
		pm.clearInfoMessage();
	}

	protected class FunctionDetailChangeListener implements ChangeListener {
		int type;
		Function[] functions;
		TaskMonitor monitor;
		VariousChoicesPanel vPanel;

		FunctionDetailChangeListener(final int type, final Function[] functions,
				final VariousChoicesPanel vPanel, final TaskMonitor monitor) {
			this.type = type;
			this.functions = functions;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			mergeFunctionDetail(type, functions, getOptionForChoice(choice), monitor);
			adjustUseForAll();
			adjustApply();
		}

		void adjustUseForAll() {
			if (mergeManager != null) {
				vPanel.adjustUseForAllEnablement();
			}
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	protected void mergeParameters(Function[] functions, int chosenConflictOption,
			TaskMonitor monitor) {

		if (functions[RESULT] == null) {
			return;
		}
		ProgramMerge pgmMerge = null;
		Address currentAddress = null;
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			pgmMerge = getMergeLatest();
			currentAddress = functions[LATEST].getEntryPoint();
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			pgmMerge = getMergeMy();
			currentAddress = functions[MY].getEntryPoint();
		}
		else {
			return;
		}
		if (pgmMerge != null) {
			pgmMerge.replaceFunctionParameters(currentAddress, monitor);
			Function f =
				pgmMerge.getOriginProgram().getFunctionManager().getFunctionAt(currentAddress);
			if (f == null) {
				return;
			}
		}
	}

	protected void mergeParamInfo(Address entryPt, List<ParamInfoConflict> paramInfoConflicts,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {
		Iterator<ParamInfoConflict> iter = paramInfoConflicts.iterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			ParamInfoConflict pc = iter.next();
			mergeParamInfo(entryPt, pc, chosenConflictOption, monitor);
		}
	}

	protected void mergeParamInfo(Address entryPt, ParamInfoConflict pc, int chosenConflictOption,
			TaskMonitor monitor) {
		int ordinal = pc.ordinal;
		int conflicts = pc.paramConflicts;
//			if ((conflicts & VAR_TYPE) != 0) {
//				mergeParameter(VAR_TYPE, entryPt, ordinal, chosenConflictOption, monitor);
//			}
		if ((conflicts & VAR_NAME) != 0) {
			mergeParameter(VAR_NAME, entryPt, ordinal, chosenConflictOption, monitor);
		}
		if ((conflicts & VAR_DATATYPE) != 0) {
			mergeParameter(VAR_DATATYPE, entryPt, ordinal, chosenConflictOption, monitor);
		}
//			if ((conflicts & VAR_LENGTH) != 0) {
//				mergeParameter(VAR_LENGTH, entryPt, ordinal, conflictOption, monitor);
//			}
		if ((conflicts & VAR_COMMENT) != 0) {
			mergeParameter(VAR_COMMENT, entryPt, ordinal, chosenConflictOption, monitor);
		}
	}

	protected void mergeParamInfo(Function[] functions, List<ParamInfoConflict> paramInfoConflicts,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {

		Iterator<ParamInfoConflict> iter = paramInfoConflicts.iterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			ParamInfoConflict pc = iter.next();
			mergeParamInfo(functions, pc, chosenConflictOption, monitor);
		}
	}

	protected void mergeParamInfo(Function[] functions, ParamInfoConflict pc,
			int chosenConflictOption, TaskMonitor monitor) {
		int ordinal = pc.ordinal;
		int conflicts = pc.paramConflicts;
//			if ((conflicts & VAR_TYPE) != 0) {
//				mergeParameter(VAR_TYPE, functions, ordinal, chosenConflictOption, monitor);
//			}
		if ((conflicts & VAR_NAME) != 0) {
			mergeParameter(VAR_NAME, functions, ordinal, chosenConflictOption, monitor);
		}
		if ((conflicts & VAR_DATATYPE) != 0) {
			mergeParameter(VAR_DATATYPE, functions, ordinal, chosenConflictOption, monitor);
		}
//			if ((conflicts & VAR_LENGTH) != 0) {
//				mergeParameter(VAR_LENGTH, functions, ordinal, conflictOption, monitor);
//			}
		if ((conflicts & VAR_COMMENT) != 0) {
			mergeParameter(VAR_COMMENT, functions, ordinal, chosenConflictOption, monitor);
		}
	}

	protected void mergeLocals(Address entryPt, List<LocalVariableConflict> localVarConflicts,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {
		Iterator<LocalVariableConflict> iter = localVarConflicts.iterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			LocalVariableConflict lvc = iter.next();
			mergeLocal(entryPt, lvc, chosenConflictOption, monitor);
		}
	}

	protected void mergeLocal(Address entryPt, LocalVariableConflict localVarConflict,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		Variable[] vars = localVarConflict.vars; // [0]=Original, [1]=Latest, [2]=My
		int conflicts = localVarConflict.varConflicts;
//			if ((conflicts & VAR_REMOVED) != 0) {
//				mergeVariable(VAR_REMOVED, entryPt, vars[ORIGINAL_VAR],
//					getProgramListingMerge(chosenConflictOption), monitor);
//				return;
//			}
		if ((conflicts & VAR_REMOVED) != 0) {
			mergeLocalVariable(VAR_REMOVED, entryPt, vars, chosenConflictOption, monitor);
			return;
		}
		if ((conflicts & VAR_NAME) != 0) {
			mergeLocalVariable(VAR_NAME, entryPt, vars, chosenConflictOption, monitor);
		}
		if ((conflicts & VAR_DATATYPE) != 0) {
			mergeLocalVariable(VAR_DATATYPE, entryPt, vars, chosenConflictOption, monitor);
		}
//				if ((conflicts & VAR_LENGTH) != 0) {
//					mergeLocalVariable(VAR_LENGTH, entryPt, vars, conflictOption, monitor);
//				}
		if ((conflicts & VAR_COMMENT) != 0) {
			mergeLocalVariable(VAR_COMMENT, entryPt, vars, chosenConflictOption, monitor);
		}
	}

	void mergeFunctionDetails(Function[] functions, int chosenConflictOption, TaskMonitor monitor) {

		Address myEntryPoint = functions[MY].getEntryPoint();
		int conflicts = 0;
		try {
			conflicts = funcConflicts.get(myEntryPoint);
		}
		catch (NoValueException e) {
			// It's okay if we don't have conflict bits set yet.
		}

		if ((conflicts & FUNC_NAME) != 0) {
			mergeFunctionDetail(FUNC_NAME, functions, chosenConflictOption, monitor);
		}
//		if ((conflicts & FUNC_RETURN_TYPE) != 0) {
//			mergeFunctionDetail(FUNC_RETURN_TYPE, functions, chosenConflictOption, monitor);
//		}
		if (((conflicts & FUNC_RETURN_ADDRESS_OFFSET) != 0) &&
			((conflicts & FUNC_SIGNATURE) == 0)) {
			mergeFunctionDetail(FUNC_RETURN_ADDRESS_OFFSET, functions, chosenConflictOption,
				monitor);
		}
// For now, we are not allowing you to set the parameter offset or local size outright.
//		if ((conflicts & FUNC_PARAMETER_OFFSET) != 0) {
//			mergeFunctionDetail(FUNC_PARAMETER_OFFSET, entryPt, chosenConflictOption, monitor);
//		}
//		if ((conflicts & FUNC_LOCAL_SIZE) != 0) {
//			mergeFunctionDetail(FUNC_LOCAL_SIZE, entryPt, chosenConflictOption, monitor);
//		}
		if ((conflicts & FUNC_STACK_PURGE_SIZE) != 0) {
			mergeFunctionDetail(FUNC_STACK_PURGE_SIZE, functions, chosenConflictOption, monitor);
		}
		if ((conflicts & FUNC_INLINE) != 0) {
			mergeFunctionDetail(FUNC_INLINE, functions, chosenConflictOption, monitor);
		}
		if ((conflicts & FUNC_NO_RETURN) != 0) {
			mergeFunctionDetail(FUNC_NO_RETURN, functions, chosenConflictOption, monitor);
		}
		if ((conflicts & FUNC_CALLING_CONVENTION) != 0) {
			mergeFunctionDetail(FUNC_CALLING_CONVENTION, functions, chosenConflictOption, monitor);
		}
		if ((conflicts & FUNC_SIGNATURE_SOURCE) != 0) {
			mergeFunctionDetail(FUNC_SIGNATURE_SOURCE, functions, chosenConflictOption, monitor);
		}
	}

	void mergeHigherPrioritySignatureSource(Function[] functions, TaskMonitor monitor) {
		int currentConflictOption = KEEP_LATEST;
		SourceType latestSignatureSource = functions[LATEST].getSignatureSource();
		SourceType mySignatureSource = functions[MY].getSignatureSource();
		if (mySignatureSource.isHigherPriorityThan(latestSignatureSource)) {
			currentConflictOption = KEEP_MY;
		}
		mergeFunctionDetail(FUNC_SIGNATURE_SOURCE, functions, currentConflictOption, monitor);
	}

	void mergeFunctionReturn(Function[] functions, int chosenConflictOption, TaskMonitor monitor) {
		Address entryPoint = getEntryPoint(functions, chosenConflictOption);
		ProgramMerge programListingMerge = getProgramListingMerge(chosenConflictOption);
		programListingMerge.mergeFunctionReturn(entryPoint);
	}

	protected VerticalChoicesPanel getEmptyVerticalPanel() {
		if (verticalConflictPanel == null) {
			verticalConflictPanel = new VerticalChoicesPanel();
		}
		runSwing(() -> verticalConflictPanel.clear());
		currentConflictPanel = verticalConflictPanel;
		return verticalConflictPanel;
	}

	protected ScrollingListChoicesPanel getEmptyScrollingListChoicesPanel() {
		if (scrollingListConflictPanel == null) {
			scrollingListConflictPanel = new ScrollingListChoicesPanel();
		}
		runSwing(() -> scrollingListConflictPanel.clear());
		currentConflictPanel = scrollingListConflictPanel;
		return scrollingListConflictPanel;
	}

	protected VariousChoicesPanel getEmptyVariousPanel() {
		if (variousConflictPanel == null) {
			variousConflictPanel = new VariousChoicesPanel();
		}
		runSwing(() -> variousConflictPanel.clear());
		currentConflictPanel = variousConflictPanel;
		return variousConflictPanel;
	}

	protected String getReturnString(Function func, boolean includeStorage) {
		// TODO: How should we format return with storage?
		// TODO: Need to somewhat standardize with function signature display 
		//  and parameter display when name, data-type and storage all should be displayed
		if (func == null) {
			return "";
		}
		Parameter returnVar = func.getReturn();
		String returnStr = returnVar.getDataType().getName();
		if (includeStorage) {
			returnStr += ", " + returnVar.getVariableStorage();
		}
		return returnStr;
	}

	protected String[] getReturnInfo(Program pgm, String returnStr, String prefix, String suffix) {
		if (pgm == null) { // Header info
			return new String[] { "Option", "Function Return" };
		}
		String[] info = new String[] { "", "" };
		String version = "";
		if (pgm == programs[ORIGINAL]) {
			version = ORIGINAL_TITLE;
		}
		else if (pgm == programs[LATEST]) {
			version = LATEST_TITLE;
		}
		else if (pgm == programs[MY]) {
			version = MY_TITLE;
		}
		else if (pgm == programs[RESULT]) {
			version = RESULT_TITLE;
		}
		info[0] = prefix + version + suffix;
		if (returnStr != null) {
			info[1] = returnStr;
		}
		return info;
	}

	protected String[] getSignatureInfo(Program pgm, Function f, String prefix, String suffix) {
		if (pgm == null) { // Header info
			return new String[] { "Option", "Signature" };
		}
		String[] info = new String[] { "", "" };
		String version = "";
		if (pgm == programs[ORIGINAL]) {
			version = ORIGINAL_TITLE;
		}
		else if (pgm == programs[LATEST]) {
			version = LATEST_TITLE;
		}
		else if (pgm == programs[MY]) {
			version = MY_TITLE;
		}
		else if (pgm == programs[RESULT]) {
			version = RESULT_TITLE;
		}
		info[0] = prefix + version + suffix;
		if (f != null) {
			info[1] = f.getPrototypeString(true, false);
		}
		return info;
	}

	void setupConflictPanel(final ListingMergePanel listingPanel, final JPanel conflictPanel,
			final Address entryPt, final TaskMonitor monitor) {

		if (conflictPanel == null) {
			Msg.showError(this, null, "Error Displaying Conflict Panel",
				"The conflict panel could not be created.");
			return;
		}

		this.currentMonitor = monitor;
		this.currentConflictPanel = (ConflictPanel) conflictPanel;

		try {
			SwingUtilities.invokeAndWait(() -> listingPanel.setBottomComponent(conflictPanel));
			SwingUtilities.invokeLater(() -> {
				// Set background color of function entry point code unit
				listingPanel.clearAllBackgrounds();
				listingPanel.paintAllBackgrounds(new AddressSet(entryPt, entryPt));
			});
		}
		catch (InterruptedException e) {
			showConflictPanelException(entryPt, e);
			return;
		}
		catch (InvocationTargetException e) {
			showConflictPanelException(entryPt, e);
			return;
		}
		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);
			mergeManager.showListingMergePanel(entryPt);
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	private void showConflictPanelException(final Address entryPt, Exception e) {
		String message = "Couldn't display conflict for function at " + entryPt.toString(true) +
			".\n " + e.getMessage();
		Msg.showError(this, mergeManager.getMergeTool().getToolFrame(), "Function Merge Error",
			message, e);
		// Should this just put a message on errorBuf instead?
	}

	/**
	 * Returns an array of strings to display for a row of variable information.
	 * @param var
	 * @param option
	 * @return
	 */
	String[] getVariableInfo(Variable var, String option) {
		if (option == null) { // Header info
			return new String[] { "Option", "Storage", "Name", "DataType", "Comment" };
		}
		String[] info = new String[] { "", "", "", "", "" };
		info[0] = option;
		if (var != null) {
			info[1] = var.getVariableStorage().toString();
			info[2] = var.getName();
			info[3] = var.getDataType().getDisplayName();
			info[4] = var.getComment();
		}
		return info;
	}

	class LocalVarChangeListener implements ChangeListener {
		int type;
		Address entryPt;
		Variable[] vars; // [0]=Original, [1]=Latest, [2]=My
		VariousChoicesPanel vPanel;
		TaskMonitor monitor;

		LocalVarChangeListener(final int type, final Address entryPt, final Variable[] vars,
				final VariousChoicesPanel vPanel, final TaskMonitor monitor) {
			this.type = type;
			this.entryPt = entryPt;
			this.vars = vars;
			this.vPanel = vPanel;
			this.monitor = monitor;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			mergeLocalVariable(type, entryPt, vars, getOptionForChoice(choice), monitor);
			adjustUseForAll();
			adjustApply();
		}

		void adjustUseForAll() {
			if (mergeManager != null) {
				vPanel.adjustUseForAllEnablement();
			}
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	/**
	 * Converts a user choice into a conflictOption
	 * @param choice the user choice
	 * @return the conflictOption
	 */
	int getOptionForChoice(int choice) {
		int associatedConflictOption = ASK_USER;
		switch (choice) {
			case 1:
				associatedConflictOption = KEEP_LATEST;
				break;
			case 2:
				associatedConflictOption = KEEP_MY;
				break;
			case 4:
				associatedConflictOption = KEEP_ORIGINAL;
				break;
		}
		return associatedConflictOption;
	}

	protected void clearConflictPanel() {
		try {
			SwingUtilities.invokeAndWait(() -> {
				if (currentConflictPanel != null) {
					currentConflictPanel.clear();
				}
			});
		}
		catch (InterruptedException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		catch (InvocationTargetException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	protected void runSwing(Runnable r) {
		try {
			SwingUtilities.invokeAndWait(r);
		}
		catch (InterruptedException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		catch (InvocationTargetException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	/**
	 * Clears all text from the error buffer.
	 */
	void clearResolveErrors() {
		if (errorBuf.length() > 0) {
			errorBuf = new StringBuffer();
		}
	}

	/**
	 * This is a generic method for displaying the contents of the error 
	 * buffer to the user.
	 */
	void showResolveErrors(final String title) {
		if (errorBuf.length() > 0) {
			try {
				SwingUtilities.invokeAndWait(() -> {
					String msg = errorBuf.toString();
					clearResolveErrors();
					ReadTextDialog dialog = new ReadTextDialog(title, msg);
					PluginTool mergeTool = mergeManager.getMergeTool();
					mergeManager.getMergeTool().showDialog(dialog, mergeTool.getActiveWindow());
				});
			}
			catch (InterruptedException e) {
				throw new AssertException(e);
			}
			catch (InvocationTargetException e) {
				throw new AssertException(e);
			}
		}
	}

	/**
	 * Clears all text from the information buffer.
	 */
	void clearResolveInfo() {
		if (infoBuf.length() > 0) {
			infoBuf = new StringBuffer();
		}
	}

	/**
	 * This is a generic method for displaying the contents of the information 
	 * buffer to the user.
	 */
	void showResolveInfo(final String title) {
		if (infoBuf.length() > 0) {
			try {
				SwingUtilities.invokeAndWait(() -> {
					String msg = infoBuf.toString();
					ReadTextDialog dialog = new ReadTextDialog(title, msg);
					PluginTool mergeTool = mergeManager.getMergeTool();
					mergeManager.getMergeTool().showDialog(dialog, mergeTool.getActiveWindow());
				});
			}
			catch (InterruptedException e) {
				throw new AssertException(e);
			}
			catch (InvocationTargetException e) {
				throw new AssertException(e);
			}
		}
	}

	protected VariousChoicesPanel createLocalVariableConflictPanel(final LocalVariableConflict lvc,
			final TaskMonitor monitor) {

		Address entryPt = lvc.entry;
		Variable[] vars = lvc.vars; // [0]=Original, [1]=Latest, [2]=My
		Variable origLocal = vars[ORIGINAL_VAR];
		Variable latestLocal = vars[LATEST_VAR];
		Variable myLocal = vars[MY_VAR];
		int conflicts = lvc.varConflicts;
//		if ((conflicts & VAR_REMOVED) != 0) {
//			return createRemovedVarConflictPanel(entryPt, vars, monitor);
//		}

		VariousChoicesPanel panel = getEmptyVariousPanel();

		runSwing(() -> {
			panel.setTitle("Function Local Variable");
			Variable var =
				(latestLocal != null) ? latestLocal : ((myLocal != null) ? myLocal : (origLocal));
			String varInfo = "Local Variable" + ConflictUtility.spaces(4) + "Storage: " +
				ConflictUtility.getEmphasizeString(var.getVariableStorage().toString()) +
				ConflictUtility.spaces(4) + "First Use Offset: " +
				ConflictUtility.getOffsetString(var.getFirstUseOffset());
			String text = "Function: " +
				ConflictUtility.getEmphasizeString(
					functionManagers[RESULT].getFunctionAt(entryPt).getName()) +
				ConflictUtility.spaces(4) + "EntryPoint: " +
				ConflictUtility.getAddressString(entryPt) + ConflictUtility.spaces(4) + varInfo;
			panel.setHeader(text);
			panel.addInfoRow("Conflict", new String[] { LATEST_TITLE, MY_TITLE }, true);

			if ((conflicts & VAR_NAME) != 0) {
				String latest = latestLocal.getName();
				String my = myLocal.getName();
				panel.addSingleChoice("Local Variable Name", new String[] { latest, my },
					new LocalVarChangeListener(VAR_NAME, entryPt, vars, panel, monitor));
			}
			if ((conflicts & VAR_DATATYPE) != 0) {
				String latest = latestLocal.getDataType().getName();
				String my = myLocal.getDataType().getName();
				panel.addSingleChoice("Local Variable Data Type", new String[] { latest, my },
					new LocalVarChangeListener(VAR_DATATYPE, entryPt, vars, panel, monitor));
			}
//		if ((conflicts & VAR_LENGTH) != 0) {
//			String latest = latestLocal.getLength();
//			String my = myLocal.getLength();
//			panel.addSingleChoice("Local Variable Length", new String[] {latest, my}, 
//					new LocalVarChangeListener(VAR_LENGTH, entryPt, vars, panel, monitor));
//		}
			if ((conflicts & VAR_COMMENT) != 0) {
				String latest = latestLocal.getComment();
				String my = myLocal.getComment();
				panel.addSingleChoice("Local Variable Comment", new String[] { latest, my },
					new LocalVarChangeListener(VAR_COMMENT, entryPt, vars, panel, monitor));
			}
		});
		return panel;
	}

	protected VerticalChoicesPanel createRemoveConflictPanel(final Function[] functions,
			final TaskMonitor monitor) {
		Address addr = functions[ORIGINAL].getEntryPoint();
		String latest = getFunctionPrompt(addr, functions[LATEST], LATEST_TITLE);
		String my = getFunctionPrompt(addr, functions[MY], MY_TITLE);

		VerticalChoicesPanel panel = getEmptyVerticalPanel();

		runSwing(() -> {
			panel.setTitle("Function Remove");
			StringBuffer buf = new StringBuffer();
			buf.append("One function was removed and the other changed @ ");
			ConflictUtility.addAddress(buf, addr);
			buf.append(".");
			panel.setHeader(buf.toString());
			ChangeListener changeListener =
				new FunctionConflictChangeListener(FUNC_REMOVE, addr, panel, monitor);
			panel.addRadioButtonRow(new String[] { latest }, LATEST_BUTTON_NAME, KEEP_LATEST,
				changeListener);
			panel.addRadioButtonRow(new String[] { my }, CHECKED_OUT_BUTTON_NAME, KEEP_MY,
				changeListener);
		});
		return panel;
	}

	class FunctionConflictChangeListener implements ChangeListener {
		int type;
		Address entryPt;
		TaskMonitor monitor;
		ConflictPanel vPanel;

		FunctionConflictChangeListener(final int type, final Address entryPt,
				final ConflictPanel vPanel, final TaskMonitor monitor) {
			this.type = type;
			this.entryPt = entryPt;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			try {
				switch (type) {
					case FUNC_BODY:
					case FUNC_REMOVE:
					case FUNC_THUNK:
						mergeFunction(entryPt, choice, currentMonitor);
						break;
				}
			}
			catch (CancelledException e1) {
				Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
			}
			adjustApply();
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	private void mergeFunction(Address entryPt, int chosenConflictOption, TaskMonitor monitor)
			throws CancelledException {
		updateProgressMessage("Merging function @ " + entryPt.toString(true));
		ProgramMerge pgmMerge = getProgramListingMerge(chosenConflictOption);
		if (pgmMerge == null) {
			return;
		}
		Program origPgm = pgmMerge.getOriginProgram();
		if (origPgm == null) {
			return;
		}
		Function f = pgmMerge.mergeFunction(entryPt, monitor);
		if (f != null) {
			try {
				Function origF = origPgm.getFunctionManager().getFunctionAt(entryPt);
				if (origF != null) {
					Namespace ns =
						listingMergeManager.resolveNamespace(origPgm, origF.getParentNamespace());
					f.setParentNamespace(ns);
				}
			}
			catch (DuplicateNameException e) {
				Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
					"Error Setting Function Namespace", e.getMessage());
			}
			catch (InvalidInputException e) {
				Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
					"Error Setting Function Namespace", e.getMessage());
			}
			catch (CircularDependencyException e) {
				Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
					"Error Setting Function Namespace", e.getMessage());
			}
		}
	}

	protected ScrollingListChoicesPanel createStorageConflictPanel(final Address entryPt,
			final Pair<List<Variable>, List<Variable>> pair, final TaskMonitor monitor) {

		getEmptyScrollingListChoicesPanel();

		final ChangeListener changeListener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				int choice =
					AbstractFunctionMerger.this.scrollingListConflictPanel.getUseForAllChoice();
				if (choice == 0) {
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(false);
					}
					return;
				}
				if (mergeManager != null) {
					mergeManager.clearStatusText();
				}
				try {
					mergeVariableStorage(entryPt, pair, getOptionForChoice(choice), monitor);
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
				catch (Exception e1) {
					Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
				}
			}
		};

		runSwing(() -> {
			scrollingListConflictPanel.setTitle("Parameter/Variable Storage");
			String text = "The function @ " + ConflictUtility.getAddressString(entryPt) +
				" has conflicting parameter/variable storage resulting from changes.<br>Choose the desired set of parameters/variables to keep.<br>";
			scrollingListConflictPanel.setHeader(text);
			scrollingListConflictPanel.setChoiceNames(LATEST_TITLE, LATEST_LIST_BUTTON_NAME,
				MY_TITLE, CHECKED_OUT_LIST_BUTTON_NAME);
			scrollingListConflictPanel.setListChoice(changeListener, STORAGE_CONFLICT_CHOICES,
				STORAGE_CONFLICT_HEADINGS, getVariableDetails(pair.first),
				getVariableDetails(pair.second));
		});

		return scrollingListConflictPanel;
	}

	protected static final String[] STORAGE_CONFLICT_CHOICES =
		new String[] { "Latest", "Checked Out" };

	protected void mergeVariableStorage(Address entryPt, Pair<List<Variable>, List<Variable>> pair,
			int currentConflictOption, TaskMonitor monitor) throws CancelledException {
		ProgramMerge pgmMerge = getProgramListingMerge(currentConflictOption);
		List<Variable> list = currentConflictOption == KEEP_LATEST ? pair.first : pair.second;
		pgmMerge.replaceVariables(entryPt, list, monitor);
	}

	protected static final String[] STORAGE_CONFLICT_HEADINGS =
		new String[] { "Parameter/First-Use", "Name", "Storage", "Data-Type" };

	protected List<String[]> getVariableDetails(List<Variable> list) {
		List<String[]> tableData = new ArrayList<>();
		for (Variable var : list) {
			String[] data = new String[4];
			data[0] = (var instanceof Parameter) ? ("Param: " + ((Parameter) var).getOrdinal())
					: var.getFunction().getEntryPoint().addWrap(var.getFirstUseOffset()).toString();
			data[1] = var.getName();
			data[2] = var.getVariableStorage().toString();
			data[3] = var.getDataType().getName();
			tableData.add(data);
		}
		return tableData;
	}

	protected VerticalChoicesPanel createParameterSigConflictPanel(final Function[] functions,
			final TaskMonitor monitor) {

		getEmptyVerticalPanel();
		final ChangeListener changeListener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				int chosenConflictOption =
					AbstractFunctionMerger.this.verticalConflictPanel.getSelectedOptions();
				if (chosenConflictOption == ListingMergeConstants.ASK_USER) {
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(false);
					}
					return;
				}
				if (mergeManager != null) {
					mergeManager.clearStatusText();
				}
				try {
					mergeParameters(functions, chosenConflictOption, monitor);
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
				catch (Exception e1) {
					Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
				}
			}
		};

		runSwing(() -> {
			verticalConflictPanel.setTitle("Function Parameters");
			String text = getConflictPrefixString(functions) +
				" has conflicting signature storage changes.<br>Choose the desired function signature.<br>" +
				"Note: If the signatures below look the same, then check for return/parameter storage differences in the Listings above.";
			verticalConflictPanel.setHeader(text);
			verticalConflictPanel.setRowHeader(getSignatureInfo(null, null, null, null));
			verticalConflictPanel.addRadioButtonRow(
				getSignatureInfo(programs[LATEST], functions[LATEST], "Use ", " version"),
				LATEST_BUTTON_NAME, KEEP_LATEST, changeListener);
			verticalConflictPanel.addRadioButtonRow(
				getSignatureInfo(programs[MY], functions[MY], "Use ", " version"),
				CHECKED_OUT_BUTTON_NAME, KEEP_MY, changeListener);
			verticalConflictPanel.addInfoRow(
				getSignatureInfo(programs[ORIGINAL], functions[ORIGINAL], "", " version"));
		});

		return verticalConflictPanel;
	}

	private String getConflictPrefixString(Function[] functions) {
		if (functions[MY].isExternal()) {
			return "The " + MY_TITLE + " external function '" +
				ConflictUtility.getEmphasizeString(functions[MY].getSymbol().getName(true)) + "'";
		}
		return "The " + RESULT_TITLE + " function '" +
			ConflictUtility.getEmphasizeString(functions[RESULT].getName()) + "' @ " +
			ConflictUtility.getAddressString(functions[RESULT].getEntryPoint());
	}

	protected VariousChoicesPanel createFunctionConflictPanel(final Function[] functions,
			final TaskMonitor monitor) {

		if (functions[RESULT] == null) {
			Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
				"Error Creating Function Conflict Panel", "RESULT function is null.");
			return null;
		}
		Address myEntryPoint = functions[MY].getEntryPoint();

		StackFrame latestStack = functions[LATEST].getStackFrame();
		StackFrame myStack = functions[MY].getStackFrame();

		VariousChoicesPanel panel = getEmptyVariousPanel();

		int conflictCount = 0;
		try {
			conflictCount = funcConflicts.get(myEntryPoint);
		}
		catch (NoValueException e) {
			Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
				"Error Creating Function Conflict Panel",
				"Couldn't get conflict information for MY function at " +
					myEntryPoint.toString(true) + ".");
			return null;
		}

		int conflicts = conflictCount;
		runSwing(() -> {

			panel.setTitle("Function");
			String text = getConflictPrefixString(functions) +
				" has conflicting changes.<br>Choose the desired result for each conflict.<br>";
			panel.setHeader(text);
			panel.addInfoRow("Conflict", new String[] { LATEST_TITLE, MY_TITLE }, true);

			if ((conflicts & FUNC_NAME) != 0) {
				String latest = functions[LATEST].getName();
				String my = functions[MY].getName();
				panel.addSingleChoice("Name", new String[] { latest, my },
					new FunctionDetailChangeListener(FUNC_NAME, functions, panel, monitor));
			}
//			if ((conflicts & FUNC_RETURN_TYPE) != 0) {
//				String latest = latestFunc.getReturnType().getName();
//				String my = myFunc.getReturnType().getName();
//				DataType latestDt = latestFunc.getReturnType();
//				DataType myDt = myFunc.getReturnType();
//				long latestID = programs[LATEST].getDataTypeManager().getID(latestDt);
//				long myID = programs[MY].getDataTypeManager().getID(myDt);
//				DataType latestResultDt = getResultDataType(latestID, programs[LATEST]);
//				DataType myResultDt = getResultDataType(myID, programs[MY]);
//				if (latestResultDt != null) {
//					latest = latestResultDt.getName();
//				}
//				if (myResultDt != null) {
//					my = myResultDt.getName();
//				}
//				panel.addSingleChoice("Return Type", new String[] { latest, my },
//					new FunctionDetailChangeListener(FUNC_RETURN_TYPE, entryPt, panel, monitor));
//			}
			if (((conflicts & FUNC_RETURN_ADDRESS_OFFSET) != 0)) {
				String latest = DiffUtility.toSignedHexString(latestStack.getReturnAddressOffset());
				String my = DiffUtility.toSignedHexString(myStack.getReturnAddressOffset());
				panel.addSingleChoice("Return Address Offset", new String[] { latest, my },
					new FunctionDetailChangeListener(FUNC_RETURN_ADDRESS_OFFSET, functions, panel,
						monitor));
			}
// For now, we are not allowing you to set the parameter offset or local size outright.
//			if ((conflicts & FUNC_PARAMETER_OFFSET) != 0) {
//				String latest = DiffUtility.toSignedHexString(latestStack.getParameterOffset());
//				String my = DiffUtility.toSignedHexString(myStack.getParameterOffset());
//				panel.addSingleChoice(
//					"Parameter Offset",
//					new String[] { latest, my },
//					new FunctionDetailChangeListener(FUNC_PARAMETER_OFFSET, entryPt, panel, monitor));
//			}
//			if ((conflicts & FUNC_LOCAL_SIZE) != 0) {
//				String latest = DiffUtility.toSignedHexString(latestStack.getLocalSize());
//				String my = DiffUtility.toSignedHexString(myStack.getLocalSize());
//				panel.addSingleChoice("Local Size", new String[] { latest, my },
//					new FunctionDetailChangeListener(FUNC_LOCAL_SIZE, entryPt, panel, monitor));
//			}
			if ((conflicts & FUNC_STACK_PURGE_SIZE) != 0) {
				String latest =
					DiffUtility.toSignedHexString(functions[LATEST].getStackPurgeSize());
				String my = DiffUtility.toSignedHexString(functions[MY].getStackPurgeSize());
				panel.addSingleChoice("Stack Purge Size", new String[] { latest, my },
					new FunctionDetailChangeListener(FUNC_STACK_PURGE_SIZE, functions, panel,
						monitor));
			}
			if ((conflicts & FUNC_INLINE) != 0) {
				String latest = Boolean.toString(functions[LATEST].isInline());
				String my = Boolean.toString(functions[MY].isInline());
				panel.addSingleChoice("Is Inline?", new String[] { latest, my },
					new FunctionDetailChangeListener(FUNC_INLINE, functions, panel, monitor));
			}
			if ((conflicts & FUNC_NO_RETURN) != 0) {
				String latest = Boolean.toString(functions[LATEST].hasNoReturn());
				String my = Boolean.toString(functions[MY].hasNoReturn());
				panel.addSingleChoice("Has No Return?", new String[] { latest, my },
					new FunctionDetailChangeListener(FUNC_NO_RETURN, functions, panel, monitor));
			}
			if ((conflicts & FUNC_CALLING_CONVENTION) != 0) {
				String latest = functions[LATEST].getCallingConventionName();
				String my = functions[MY].getCallingConventionName();
				panel.addSingleChoice("Calling Convention", new String[] { latest, my },
					new FunctionDetailChangeListener(FUNC_CALLING_CONVENTION, functions, panel,
						monitor));
			}
//		if ((conflicts & FUNC_CUSTOM_STORAGE) != 0) {
//			String latest = Boolean.toString(functions[LATEST].hasCustomVariableStorage());
//			String my = Boolean.toString(functions[MY].hasCustomVariableStorage());
//			panel.addSingleChoice("Custom Storage", new String[] { latest, my },
//				new FunctionDetailChangeListener(FUNC_CUSTOM_STORAGE, functions, panel, monitor));
//		}
			if ((conflicts & FUNC_SIGNATURE_SOURCE) != 0) {
				SourceType latest = functions[LATEST].getSignatureSource();
				SourceType my = functions[MY].getSignatureSource();
				panel.addSingleChoice("Signature Source",
					new String[] { latest.toString(), my.toString() },
					new FunctionDetailChangeListener(FUNC_SIGNATURE_SOURCE, functions, panel,
						monitor));
			}

		});
		return panel;
	}

	protected VerticalChoicesPanel createFunctionReturnConflictPanel(final Function[] functions,
			final TaskMonitor monitor) {

		getEmptyVerticalPanel();
		final ChangeListener changeListener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				int chosenConflictOption =
					AbstractFunctionMerger.this.verticalConflictPanel.getSelectedOptions();
				if (chosenConflictOption == ListingMergeConstants.ASK_USER) {
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(false);
					}
					return;
				}
				if (mergeManager != null) {
					mergeManager.clearStatusText();
				}
				try {
					mergeFunctionReturn(functions, chosenConflictOption, monitor);
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
				catch (Exception e1) {
					Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
				}
			}
		};

		runSwing(() -> {
			verticalConflictPanel.setTitle("Function Return");
			String text = getConflictPrefixString(functions) +
				" has conflicting Return changes.<br>Choose the desired Return.<br>";
			verticalConflictPanel.setHeader(text);
			verticalConflictPanel.setRowHeader(getReturnInfo(null, null, null, null));
			boolean hasCustomerStorage = functions[RESULT].hasCustomVariableStorage();
			verticalConflictPanel.addRadioButtonRow(
				getReturnInfo(programs[LATEST],
					getReturnString(functions[LATEST], hasCustomerStorage), "Use ", " version"),
				LATEST_BUTTON_NAME, KEEP_LATEST, changeListener);
			verticalConflictPanel.addRadioButtonRow(getReturnInfo(programs[MY],
				getReturnString(functions[MY], hasCustomerStorage), "Use ", " version"),
				CHECKED_OUT_BUTTON_NAME, KEEP_MY, changeListener);
			verticalConflictPanel.addInfoRow(getReturnInfo(programs[ORIGINAL],
				getReturnString(functions[ORIGINAL], hasCustomerStorage), "", " version"));

		});

		return verticalConflictPanel;
	}

	/**
	 * Creates the panel for resolving a conflict due to a variable being removed.
	 * @param lvc the local variable conflict
	 * @param monitor status monitor
	 * @return the panel
	 */
	protected VerticalChoicesPanel createRemovedVarConflictPanel(final LocalVariableConflict lvc,
			final TaskMonitor monitor) {

		final ChangeListener changeListener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				clearResolveInfo();
				int chosenConflictOption = verticalConflictPanel.getSelectedOptions();
				if (chosenConflictOption == ListingMergeConstants.ASK_USER) {
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(false);
					}
					return;
				}
				if (mergeManager != null) {
					mergeManager.clearStatusText();
				}
				try {
					mergeLocalVariable(VAR_REMOVED, lvc.entry, lvc.vars, chosenConflictOption,
						monitor);
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
				catch (Exception e1) {
					String msg = "Failed to resolve variable '" +
						((lvc.vars[ORIGINAL_VAR] != null) ? lvc.vars[ORIGINAL_VAR].getName() : "") +
						"'.";
					Msg.showError(this, null, "Resolve Variable Error", msg, e1);
				}
				showResolveInfo(getInfoTitle());
			}
		};

		VerticalChoicesPanel panel = getEmptyVerticalPanel();

		runSwing(() -> {
			panel.setTitle("Function Variable Remove");
			StringBuffer buf = new StringBuffer();
			buf.append("Function variable was removed in one version and changed in the other @ ");
			ConflictUtility.addAddress(buf, lvc.entry);
			buf.append(".");
			panel.setHeader(buf.toString());
			String origPrefix = "'";
			String latestPrefix =
				(lvc.vars[LATEST_VAR] == null) ? "Remove as in '" : "Change as in '";
			String myPrefix = (lvc.vars[MY_VAR] == null) ? "Remove as in '" : "Change as in '";
			String suffix = "' version";
			panel.setRowHeader(getVariableInfo(null, null));
			panel.addRadioButtonRow(
				getVariableInfo(lvc.vars[LATEST_VAR], latestPrefix + LATEST_TITLE + suffix),
				LATEST_BUTTON_NAME, KEEP_LATEST, changeListener);
			panel.addRadioButtonRow(getVariableInfo(lvc.vars[MY_VAR], myPrefix + MY_TITLE + suffix),
				CHECKED_OUT_BUTTON_NAME, KEEP_MY, changeListener);
			panel.addInfoRow(
				getVariableInfo(lvc.vars[ORIGINAL_VAR], origPrefix + ORIGINAL_TITLE + suffix));
		});
		return panel;
	}

	protected String getFunctionPrompt(Address addr, Function function, String version) {
		if (function == null) {
			return "Delete function as in '" + version + "' version.";
		}
		return "Keep function '" + function.getName() + "' as in '" + version + "' version.";
	}

	/**
	 * Updates the progress message details associated with this phase of the merge.
	 * @param message a message indicating what is currently occurring in this phase.
	 * Null indicates to use the default message.
	 */
	protected void updateProgressMessage(String message) {
		mergeManager.updateProgress(message);
	}

	public void dispose() {
		errorBuf = null;
		infoBuf = null;

		mergeManager = null;
		programs = new Program[4];
		functionManagers = new FunctionManager[4];

		listingMergeManager = null;

		resultAddressFactory = null;

		latestResolvedDts = null; // maps data type ID -> resolved Data type
		myResolvedDts = null; // maps data type ID -> resolved Data type
		origResolvedDts = null;

		listingMergePanel = null;

		verticalConflictPanel = null;
		variousConflictPanel = null;
		scrollingListConflictPanel = null;
		currentConflictPanel = null;
		currentMonitor = null;

		removeSet = null;
		funcConflicts = null;
		funcSet = null;
	}
}
