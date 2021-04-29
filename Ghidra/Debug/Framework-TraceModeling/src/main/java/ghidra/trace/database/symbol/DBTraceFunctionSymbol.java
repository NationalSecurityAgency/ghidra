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
package ghidra.trace.database.symbol;

import java.io.IOException;
import java.util.*;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import com.google.common.collect.Collections2;
import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.VariableUtilities.VariableConflictHandler;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.DBTraceUtils.AddressDBFieldCodec;
import ghidra.trace.database.DBTraceUtils.DecodesAddresses;
import ghidra.trace.database.bookmark.DBTraceBookmarkType;
import ghidra.trace.database.listing.DBTraceCommentAdapter;
import ghidra.trace.database.listing.DBTraceData;
import ghidra.trace.database.program.DBTraceProgramView;
import ghidra.trace.database.symbol.DBTraceSymbolManager.DBTraceFunctionTag;
import ghidra.trace.database.symbol.DBTraceSymbolManager.DBTraceFunctionTagMapping;
import ghidra.trace.model.Trace.*;
import ghidra.trace.model.symbol.TraceFunctionSymbol;
import ghidra.trace.model.symbol.TraceLocalVariableSymbol;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceFunctionSymbol extends DBTraceNamespaceSymbol
		implements TraceFunctionSymbol, DecodesAddresses {
	@SuppressWarnings("hiding")
	static final String TABLE_NAME = "Functions";

	private static final byte CUSTOM_STORAGE_MASK = (byte) 0x80;
	private static final byte CUSTOM_STORAGE_CLEAR = ~CUSTOM_STORAGE_MASK;

	private static final byte NO_RETURN_MASK = 0x40;
	private static final byte NO_RETURN_CLEAR = ~NO_RETURN_MASK;

	private static final byte VAR_ARGS_MASK = 0x20;
	private static final byte VAR_ARGS_CLEAR = ~VAR_ARGS_MASK;

	private static final byte INLINE_MASK = 0x10;
	private static final byte INLINE_CLEAR = ~INLINE_MASK;

	static final String ENTRY_COLUMN_NAME = "Entry";
	static final String START_SNAP_COLUMN_NAME = "Start";
	static final String END_SNAP_COLUMN_NAME = "End";
	static final String THUNKED_COLUMN_NAME = "Thunked";
	// TODO: Why aren't fixups stored like calling conventions, by ID? Infrequent use?
	static final String FIXUP_COLUMN_NAME = "Fixup";
	static final String CALLING_CONVENTION_COLUMN_NAME = "CallingConvention";
	static final String SIGNATURE_SOURCE_COLUMN_NAME = "SignatureSource";
	static final String STACK_PURGE_COLUMN_NAME = "StackPurge";
	static final String STACK_RETURN_OFFSET_COLUMN_NAME = "ReturnOffset";

	@DBAnnotatedColumn(ENTRY_COLUMN_NAME)
	static DBObjectColumn ENTRY_COLUMN;
	@DBAnnotatedColumn(START_SNAP_COLUMN_NAME)
	static DBObjectColumn START_SNAP_COLUMN;
	@DBAnnotatedColumn(END_SNAP_COLUMN_NAME)
	static DBObjectColumn END_SNAP_COLUMN;
	@DBAnnotatedColumn(THUNKED_COLUMN_NAME)
	static DBObjectColumn THUNKED_COLUMN;
	@DBAnnotatedColumn(FIXUP_COLUMN_NAME)
	static DBObjectColumn FIXUP_COLUMN;
	@DBAnnotatedColumn(CALLING_CONVENTION_COLUMN_NAME)
	static DBObjectColumn CALLING_CONVENTION_COLUMN;
	@DBAnnotatedColumn(SIGNATURE_SOURCE_COLUMN_NAME)
	static DBObjectColumn SIGNATURE_SOURCE_COLUMN;
	@DBAnnotatedColumn(STACK_PURGE_COLUMN_NAME)
	static DBObjectColumn STACK_PURGE_COLUMN;
	@DBAnnotatedColumn(STACK_RETURN_OFFSET_COLUMN_NAME)
	static DBObjectColumn STACK_RETURN_OFFSET_COLUMN;

	@DBAnnotatedField(column = ENTRY_COLUMN_NAME, codec = AddressDBFieldCodec.class)
	protected Address entryPoint; // Do I need to index entry, too? Not just body?
	@DBAnnotatedField(column = START_SNAP_COLUMN_NAME)
	protected long startSnap;
	@DBAnnotatedField(column = END_SNAP_COLUMN_NAME)
	protected long endSnap;
	@DBAnnotatedField(column = THUNKED_COLUMN_NAME, indexed = true)
	protected long thunkedKey = -1;
	@DBAnnotatedField(column = FIXUP_COLUMN_NAME)
	protected String callFixup;
	@DBAnnotatedField(column = CALLING_CONVENTION_COLUMN_NAME)
	protected byte callingConventionID = DBTraceSymbolManager.DEFAULT_CALLING_CONVENTION_ID;
	// TODO: Pack into flags if more bits needed
	@DBAnnotatedField(column = SIGNATURE_SOURCE_COLUMN_NAME)
	protected SourceType signatureSource = SourceType.ANALYSIS; // Assumed default, 0-ordinal
	@DBAnnotatedField(column = STACK_PURGE_COLUMN_NAME)
	protected int stackPurge;
	@DBAnnotatedField(column = STACK_RETURN_OFFSET_COLUMN_NAME)
	protected int stackReturnOffset;

	protected Range<Long> lifespan;
	protected DBTraceFunctionSymbol thunked;

	protected List<DBTraceLocalVariableSymbol> locals;
	protected List<DBTraceParameterSymbol> params;
	protected DBTraceParameterSymbol ret;
	protected List<AutoParameterImpl> autoParams;

	protected final DBTraceFunctionStackFrame frame;

	protected boolean foundBadVariables = false;

	public DBTraceFunctionSymbol(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(manager, store, record);
		this.frame = new DBTraceFunctionStackFrame(this);
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}

		lifespan = DBTraceUtils.toRange(startSnap, endSnap);
		thunked = thunkedKey == -1 ? null : manager.functionStore.getObjectAt(thunkedKey);
	}

	@Override
	public Address decodeAddress(int spaceId, long offset) {
		return manager.trace.getBaseAddressFactory().getAddress(spaceId, offset);
	}

	protected void set(Range<Long> lifespan, Address entryPoint, String name,
			DBTraceFunctionSymbol thunked, DBTraceNamespaceSymbol parent, SourceType source) {
		// Recall: Signature source and symbol source are different fields
		this.name = name;
		this.parentID = parent.getID();
		doSetSource(source);
		this.entryPoint = entryPoint;
		this.startSnap = DBTraceUtils.lowerEndpoint(lifespan);
		this.endSnap = DBTraceUtils.upperEndpoint(lifespan);
		this.thunkedKey = thunked == null ? -1 : thunked.getKey();

		update(NAME_COLUMN, PARENT_COLUMN, START_SNAP_COLUMN, END_SNAP_COLUMN, FLAGS_COLUMN,
			ENTRY_COLUMN, THUNKED_COLUMN);

		this.parent = parent;
		this.lifespan = lifespan;
		this.thunked = thunked;
	}

	@Override
	protected void validateNameAndParent(String newName, DBTraceNamespaceSymbol newParent)
			throws DuplicateNameException {
		/**
		 * Nothing. Since functions cannot overlap, and each's "address" is its entry point, there
		 * cannot possibly exist duplicate <name, entry> pairs. The existing checks subsume this
		 * check.
		 */
	}

	protected void doCreateReturnParameter() {
		ret = manager.parameterStore.create();
		ret.set(Parameter.RETURN_NAME, this, DataType.DEFAULT, VariableStorage.UNASSIGNED_STORAGE,
			Parameter.RETURN_ORIDINAL, SourceType.DEFAULT);
	}

	protected static boolean isBadVariable(AbstractDBTraceVariableSymbol var) {
		return var.getAddress() == Address.NO_ADDRESS || var.getVariableStorage().isBadStorage();
	}

	/**
	 * NOTE: Caller must have at least a read lock
	 */
	protected void doLoadVariables() {
		if (!doLoadSymbolBasedVariables()) {
			return;
		}
		// NOTE: Unlike FunctionDB, going to handle custom/dynamic storage at getters.
	}

	protected boolean doLoadSymbolBasedVariables() {
		if (locals != null) {
			return false;
		}
		locals = new ArrayList<>();
		params = new ArrayList<>();
		for (DBTraceLocalVariableSymbol lVar : manager.localVars.getChildren(this)) {
			// TODO: Check for bad variables / bad storage
			locals.add(lVar);
		}
		for (DBTraceParameterSymbol pVar : manager.parameters.getChildren(this)) {
			// TODO: Bad?
			params.add(pVar);
		}
		// TODO: What is a bad variable?
		locals.sort(VariableUtilities::compare);
		params.sort(Comparator.comparing(DBTraceParameterSymbol::getOrdinal));
		ret = params.remove(0);
		assert ret.getOrdinal() == Parameter.RETURN_ORIDINAL;
		return true;
	}

	protected void doRenumberParameterOrdinals() {
		int ordinal = autoParams == null ? 0 : autoParams.size();
		for (DBTraceParameterSymbol param : params) {
			param.setOrdinal(ordinal++);
		}
	}

	protected void doPurgeBadVariables() {
		if (!foundBadVariables) {
			return;
		}
		List<AbstractDBTraceVariableSymbol> badns = new ArrayList<>();
		badns.addAll(Collections2.filter(manager.allLocals.getChildren(this),
			DBTraceFunctionSymbol::isBadVariable));
		if (badns.isEmpty()) {
			return;
		}
		DBTraceBookmarkType errType =
			manager.trace.getBookmarkManager().getOrDefineBookmarkType(BookmarkType.ERROR);
		manager.trace.getBookmarkManager()
				.addBookmark(getLifespan(), entryPoint, errType,
					"Bad Variables Removed", "Removed " + badns.size() + " bad variables");
		for (AbstractDBTraceVariableSymbol s : badns) {
			s.delete();
		}
		if (hasCustomVariableStorage()) {
			DBTraceParameterSymbol retVar = getReturn();
			if (retVar.getVariableStorage().isBadStorage()) {
				DataType dt = retVar.getDataType();
				retVar.doSetStorageAndDataType(getDynamicReturnStorage(dt), dt);
			}
		}
	}

	protected static SourceType max(SourceType a, SourceType b) {
		return a == b || a.isHigherPriorityThan(b) ? a : b;
	}

	protected void doUpdateSignatureSourceAfterVariableChange(SourceType source, DataType dt) {
		if (Undefined.isUndefined(dt)) {
			return;
		}
		SourceType highest = max(SourceType.ANALYSIS, max(source, signatureSource));
		if (signatureSource != highest) {
			signatureSource = highest;
			update(SIGNATURE_SOURCE_COLUMN);
		}
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
	public void setEndSnap(long endSnap) {
		if (this.endSnap == endSnap) {
			return;
		}
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			Range<Long> newLifespan = DBTraceUtils.toRange(startSnap, endSnap);
			this.endSnap = endSnap;
			update(END_SNAP_COLUMN);

			Range<Long> oldLifespan = lifespan;
			this.lifespan = newLifespan;

			manager.trace.setChanged(new TraceChangeRecord<>(TraceSymbolChangeType.LIFESPAN_CHANGED,
				getSpace(), this, oldLifespan, newLifespan));
		}
	}

	@Override
	public long getEndSnap() {
		return endSnap;
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.FUNCTION;
	}

	@Override
	protected Pair<String, SourceType> validateNameAndSource(String newName, SourceType newSource)
			throws InvalidInputException {
		if (newName == null || "".contentEquals(newName) ||
			SymbolUtilities.getDefaultFunctionName(entryPoint).equals(newName)) {
			return new ImmutablePair<>("", SourceType.DEFAULT);
		}
		if (newSource == SourceType.DEFAULT) {
			throw new IllegalArgumentException(
				"Cannot assign non-default name with DEFAULT source");
		}
		return new ImmutablePair<>(newName, newSource);
	}

	@Override
	public String getName() {
		if (getSource() == SourceType.DEFAULT) {
			if (thunked != null) {
				if (thunked.getSource() == SourceType.DEFAULT && thunked.thunked == null) {
					return "thunk_" + thunked.getName();
				}
				return thunked.getName();
			}
			return SymbolUtilities.getDefaultFunctionName(entryPoint);
		}
		return super.getName();
	}

	@Override
	public Address getAddress() {
		return entryPoint;
	}

	@Override
	public void setCallFixup(String newCallFixup) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.setCallFixup(newCallFixup);
				return;
			}
			String oldCallFixup = this.callFixup;
			if (Objects.equals(oldCallFixup, newCallFixup)) {
				return;
			}
			this.callFixup = newCallFixup;
			update(FIXUP_COLUMN);
			manager.trace.setChanged(
				new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED_CALL_FIXUP, getSpace(),
					this, oldCallFixup, newCallFixup));
		}
	}

	@Override
	public String getCallFixup() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getCallFixup();
			}
			return callFixup;
		}
	}

	public String getComment(int commentType) {
		return manager.trace.getCommentAdapter().getComment(startSnap, entryPoint, commentType);
	}

	@Override
	public String getComment() {
		return getComment(CodeUnit.PLATE_COMMENT);
	}

	@Override
	public String[] getCommentAsArray() {
		return DBTraceCommentAdapter.arrayFromComment(getComment());
	}

	public void setComment(int commentType, String comment) {
		manager.trace.getCommentAdapter().setComment(lifespan, entryPoint, commentType, comment);
	}

	@Override
	public void setComment(String comment) {
		setComment(CodeUnit.PLATE_COMMENT, comment);
	}

	@Override
	public String getRepeatableComment() {
		return getComment(CodeUnit.REPEATABLE_COMMENT);
	}

	@Override
	public String[] getRepeatableCommentAsArray() {
		return DBTraceCommentAdapter.arrayFromComment(getRepeatableComment());
	}

	@Override
	public void setRepeatableComment(String comment) {
		setComment(CodeUnit.REPEATABLE_COMMENT, comment);
	}

	@Override
	public Address getEntryPoint() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return entryPoint;
		}
	}

	@Override
	public DataType getReturnType() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return getReturn().getDataType();
		}
	}

	@Override
	public void setReturnType(DataType type, SourceType source) throws InvalidInputException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			getReturn().setDataType(type, source);
		}
	}

	@Override
	public DBTraceParameterSymbol getReturn() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getReturn();
			}
			doLoadVariables();
			return ret;
		}
	}

	@Override
	public void setReturn(DataType type, VariableStorage storage, SourceType source)
			throws InvalidInputException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.setReturn(type, storage, source);
				return;
			}
			type = type.clone(manager.dataTypeManager);
			if (storage.isValid() && (storage.size() != type.getLength())) {
				storage = VariableUtilities.resizeStorage(storage, type, true, this);
				// TODO: Why does FunctionDB catch Exception and ignore here?
			}
			getReturn().setDataType(type, storage, true, source);
		}
	}

	@Override
	public FunctionSignature getSignature() {
		return getSignature(false);
	}

	@Override
	public FunctionSignature getSignature(boolean formalSignature) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked == null) {
				doLoadVariables();
			}
			return new FunctionDefinitionDataType(this, formalSignature);
		}
	}

	protected boolean hasExplicitCallingConvention() {
		return callingConventionID != -1 && callingConventionID != -2;
	}

	@Override
	public String getPrototypeString(boolean formalSignature, boolean includeCallingConvention) {
		// TODO: Seems this could be extracted to a static utility....
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked == null) {
				// NOTE: Can't use thunk's getPrototypeString, in case name is different.
				doLoadVariables();
			}
			StringBuilder sb = new StringBuilder();
			DBTraceParameterSymbol retVar = getReturn();
			sb.append((formalSignature ? retVar.getFormalDataType()
					: retVar.getDataType()).getDisplayName());
			sb.append(' ');
			if (includeCallingConvention && hasExplicitCallingConvention()) {
				String cc = getCallingConventionName();
				sb.append(cc);
				sb.append(' ');
			}
			sb.append(getName());
			sb.append('(');

			Parameter[] parameters = getParameters();
			int n = parameters.length;
			boolean emptyList = true;
			for (int i = 0; i < n; i++) {
				Parameter param = parameters[i];
				if (formalSignature && param.isAutoParameter()) {
					continue;
				}
				DataType dt = formalSignature ? param.getFormalDataType() : param.getDataType();
				sb.append(dt.getDisplayName());
				sb.append(' ');
				sb.append(param.getName());
				emptyList = false;
				if (i < (n - 1)) {
					sb.append(", ");
				}
			}
			if (hasVarArgs()) {
				sb.append(", ");
				sb.append(FunctionSignature.VAR_ARGS_DISPLAY_STRING);
			}
			else if (emptyList && getSignatureSource() != SourceType.DEFAULT) {
				sb.append(FunctionSignature.VOID_PARAM_DISPLAY_STRING);
			}
			sb.append(")");

			return sb.toString();
		}
	}

	@Override
	public SourceType getSignatureSource() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getSignatureSource();
			}
			// Force DEFAULT if any param has unassigned storage
			if (!getReturn().isValid()) {
				return SourceType.DEFAULT;
			}
			for (Parameter param : getParameters()) {
				if (!param.isValid()) {
					return SourceType.DEFAULT;
				}
			}
			return signatureSource;
		}
	}

	@Override
	public void setSignatureSource(SourceType signatureSource) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.setSignatureSource(signatureSource);
				return;
			}
			this.signatureSource = signatureSource;
			update(SIGNATURE_SOURCE_COLUMN);
		}
	}

	@Override
	public StackFrame getStackFrame() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getStackFrame();
			}
			return frame;
		}
	}

	@Override
	public int getStackPurgeSize() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getStackPurgeSize();
			}
			return stackPurge;
		}
	}

	@Override
	public Set<FunctionTag> getTags() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Set<FunctionTag> result = new HashSet<>();
			// TODO: Cache the result?
			for (DBTraceFunctionTagMapping mapping : manager.tagMappingsByFunc.get(getKey())) {
				result.add(manager.tagStore.getObjectAt(mapping.getTagKey()));
			}
			return result;
		}
	}

	@Override
	public boolean addTag(String tagName) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			DBTraceFunctionTag tag = manager.tagsByName.getOne(tagName);
			if (tag != null) {
				for (DBTraceFunctionTagMapping mapping : manager.tagMappingsByFunc.get(getKey())) {
					if (mapping.getTagKey() == tag.getKey()) {
						return false;
					}
				}
			}
			else {
				// TODO: Factor tag find/create to manager?
				tag = manager.tagStore.create();
				tag.setName(tagName);
				manager.trace.setChanged(
					new TraceChangeRecord<>(TraceFunctionTagChangeType.ADDED, null, tag));
			}
			DBTraceFunctionTagMapping mapping = manager.tagMappingStore.create();
			mapping.set(this, tag);
			manager.trace.setChanged(new TraceChangeRecord<>(TraceFunctionChangeType.TAG_APPLIED,
				getSpace(), this, null, tag));
			return true;
		}
	}

	@Override
	public void removeTag(String tagName) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			DBTraceFunctionTag tag = manager.tagsByName.getOne(tagName);
			if (tag == null) {
				return;
			}
			for (DBTraceFunctionTagMapping mapping : manager.tagMappingsByFunc.get(getKey())) {
				if (mapping.getTagKey() == tag.getKey()) {
					manager.tagMappingStore.delete(mapping);
					manager.trace.setChanged(new TraceChangeRecord<>(
						TraceFunctionChangeType.TAG_REMOVED, getSpace(), this, tag, null));
				}
			}
		}
	}

	@Override
	public void setStackPurgeSize(int newStackPurge) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.setStackPurgeSize(newStackPurge);
				return;
			}
			int oldStackPurge = this.stackPurge;
			if (oldStackPurge == newStackPurge) {
				return;
			}
			this.stackPurge = newStackPurge;
			update(STACK_PURGE_COLUMN);
			manager.trace.setChanged(new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED_PURGE,
				getSpace(), this, oldStackPurge, newStackPurge));
		}
	}

	@Override
	public boolean isStackPurgeSizeValid() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.isStackPurgeSizeValid();
			}
			return stackPurge < 1 << 24;
		}
	}

	protected Variable resolveVariable(Variable var, boolean voidOK, boolean useUnassignedStorage)
			throws InvalidInputException {
		DataType dt = var.getDataType();
		if (var instanceof Parameter) {
			dt = ((Parameter) var).getFormalDataType();
		}
		DBTraceProgramView program = getProgram();
		dt = VariableUtilities.checkDataType(dt, voidOK, Math.min(1, var.getLength()), program);
		DataType resolvedDt = manager.dataTypeManager.resolve(dt, null);
		VariableStorage storage = VariableStorage.UNASSIGNED_STORAGE;
		if (!useUnassignedStorage) {
			storage = var.getVariableStorage();
			if (storage.isAutoStorage()) {
				storage = new VariableStorage(program, storage.getVarnodes());
			}
			if (resolvedDt.getLength() != storage.size()) {
				storage = VariableUtilities.resizeStorage(storage, resolvedDt, true, this);
				// TODO: Why does FunctionDB catch Exception and ignore?
			}
		}

		LocalVariableImpl resolvedVar = new LocalVariableImpl(var.getName(),
			var.getFirstUseOffset(), resolvedDt, storage, true, program, var.getSource());
		resolvedVar.setComment(var.getComment());
		return resolvedVar;
	}

	protected static VariableStorage getDynamicReturnStorage(DataType dt) {
		DataType baseType = DBTraceData.getBaseDataType(dt);
		return baseType instanceof VoidDataType ? VariableStorage.VOID_STORAGE
				: VariableStorage.UNASSIGNED_STORAGE;
	}

	protected void doUpdateParametersAndReturn() {
		if (params == null) {
			doLoadVariables();
			// Don't return, since my impl doesn't call me from load
		}

		if (hasCustomVariableStorage()) {
			autoParams = null;
			doRenumberParameterOrdinals();
			return;
		}

		DataType[] dataTypes = new DataType[params.size() + 1];
		// NOTE: Returned data type is affected by storage
		// Set storage before getting data type. Can I use getFormalDataType instead.
		for (int i = 0; i < params.size(); i++) {
			DBTraceParameterSymbol param = params.get(i);
			param.doSetDynamicStorage(VariableStorage.UNASSIGNED_STORAGE);
			dataTypes[i + 1] = param.getDataType();
		}

		dataTypes[0] = ret.getFormalDataType();
		ret.doSetDynamicStorage(getDynamicReturnStorage(dataTypes[0]));

		PrototypeModel cc = getCallingConvention();
		if (cc == null) {
			cc = manager.functions.getDefaultCallingConvention();
		}
		if (cc == null) {
			return;
		}

		VariableStorage[] storages = cc.getStorageLocations(getProgram(), dataTypes, true);
		ret.doSetDynamicStorage(storages[0]);

		int autoIndex = 0;
		int paramIndex = 0;

		autoParams = null;

		for (int i = 1; i < storages.length; i++) {
			VariableStorage s = storages[i];
			if (s.isAutoStorage()) {
				if (autoParams == null) {
					autoParams = new ArrayList<>();
				}
				DataType dt = VariableUtilities.getAutoDataType(this, ret.getFormalDataType(), s);
				try {
					autoParams.add(new AutoParameterImpl(dt, autoIndex++, s, this));
				}
				catch (InvalidInputException e) {
					throw new AssertionError(e);
					// TODO: Relax this?
				}
			}
			else {
				params.get(paramIndex++).doSetDynamicStorage(s);
			}
		}
		doRenumberParameterOrdinals();
	}

	@Override
	public DBTraceParameterSymbol addParameter(Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		return insertParameter(getParameterCount(), var, source);
	}

	@Override
	public DBTraceParameterSymbol insertParameter(int ordinal, Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				return thunked.insertParameter(ordinal, var, source);
			}
			doLoadVariables();
			doPurgeBadVariables();

			int autoCnt = autoParams == null ? 0 : autoParams.size();

			int index = ordinal - autoCnt;
			if (index < 0 || index > params.size()) {
				throw new IndexOutOfBoundsException("Ordinal value must be in [" + autoCnt + ".." +
					(params.size() + autoCnt) + "]: " + ordinal);
			}
			assertNotUniqueSpace(var);

			boolean hasCustomStorage = hasCustomVariableStorage();
			if (hasCustomStorage) {
				if (var.hasStackStorage()) {
					int stackOffset = (int) var.getLastStorageVarnode().getOffset();
					if (!frame.isParameterOffset(stackOffset)) {
						throw new InvalidInputException(
							"Variable contains invalid stack parameter offset: " + var.getName() +
								" offset " + stackOffset);
					}
				}
			}

			var = resolveVariable(var, false, !hasCustomStorage);

			String varName = var.getName();
			SourceType paramSource = source;
			// NOTE null and 0-length checks in isDefaultParameterName
			if (paramSource == SourceType.DEFAULT ||
				SymbolUtilities.isDefaultParameterName(varName)) {
				varName = "";
				paramSource = SourceType.DEFAULT;
			}

			VariableStorage storage = var.getVariableStorage();
			if (!hasCustomStorage) {
				storage = VariableStorage.UNASSIGNED_STORAGE;
			}
			else if (storage.isAutoStorage()) {
				storage = new VariableStorage(getProgram(), storage.getVarnodes());
			}

			try {
				// Check for overlapping parameter in storage
				DBTraceParameterSymbol p = null;
				if (storage != VariableStorage.UNASSIGNED_STORAGE) {
					for (DBTraceParameterSymbol oldParam : params) {
						if (oldParam.getVariableStorage().intersects(storage)) {
							p = oldParam;
							break;
						}
						VariableUtilities.checkVariableConflict(this, (p != null ? p : var),
							storage, true);
					}
				}
				if (p != null) {
					// storage has been specified
					// move and update existing parameter
					if (index >= params.size()) {
						index = params.size() - 1;
					}
					Msg.warn(this, "Inserting overlapping parameter for function " + this + " at " +
						p.getVariableStorage() + " - Replacing existing parameter!");
					if (p.getOrdinal() - autoCnt != index) {
						if (p != params.remove(p.getOrdinal() - autoCnt)) {
							throw new AssertionError("Inconsistent function parameter cache");
						}

						params.add(index, p);
						doUpdateParametersAndReturn();

						manager.trace.setChanged(
							new TraceChangeRecord<>(TraceSymbolChangeType.CHANGED, getSpace(), p));
					}
					if (!"".equals(varName)) {
						p.setName(varName, paramSource);
					}
					p.doSetStorageAndDataType(storage, var.getDataType());
				}
				else {
					// create a new parameter
					if (index > params.size()) {
						index = params.size();
					}
					// NOTE: Removed ordinal modifications. Will be done in doUpdateParams...
					p = manager.parameterStore.create();
					p.set(varName, this, var.getDataType(), storage, ordinal, paramSource);
					params.add(index, p);
					doUpdateParametersAndReturn();

					manager.trace.setChanged(
						new TraceChangeRecord<>(TraceSymbolChangeType.ADDED, getSpace(), p));
				}
				if (var.getComment() != null) {
					p.setComment(var.getComment());
				}
				doUpdateSignatureSourceAfterVariableChange(source, p.getDataType());
				return p;
			}
			finally {
				frame.invalidate();
			}
		}
	}

	@Override
	public void replaceParameters(List<? extends Variable> newParams, FunctionUpdateType updateType,
			boolean force, SourceType source) throws DuplicateNameException, InvalidInputException {
		updateFunction(null, null, newParams, updateType, force, source);
	}

	@Override
	public void replaceParameters(FunctionUpdateType updateType, boolean force, SourceType source,
			Variable... newParams) throws DuplicateNameException, InvalidInputException {
		updateFunction(null, null, Arrays.asList(newParams), updateType, force, source);
	}

	@Override
	public void updateFunction(String callingConvention, Variable returnVar,
			FunctionUpdateType updateType, boolean force, SourceType source, Variable... newParams)
			throws DuplicateNameException, InvalidInputException {
		updateFunction(callingConvention, returnVar, Arrays.asList(newParams), updateType, force,
			source);
	}

	protected static void doCheckForParameterNameConflict(Variable param,
			Collection<? extends Variable> newParams, Collection<String> nonParamNames)
			throws DuplicateNameException {
		String name = param.getName();

		if (name == null || name.length() == 0 || SymbolUtilities.isDefaultParameterName(name)) {
			return;
		}

		for (Variable chk : newParams) {
			if (param == chk) {
				continue;
			}
			if (name.equals(chk.getName())) {
				throw new DuplicateNameException("Duplicate parameter name '" + name + "'");
			}
		}
		if (nonParamNames.contains(name)) {
			throw new DuplicateNameException("Duplicate variable name '" + name + "'");
		}
	}

	protected void doCheckStorageConflicts(List<? extends Variable> newParams,
			boolean removeConflictingLocals) throws VariableSizeException {
		VariableConflictHandler localConflictHandler = removeConflictingLocals ? conflicts -> {
			for (Variable var : conflicts) {
				removeVariable(var);
			}
			return true;
		} : null;

		for (Variable p : newParams) {
			VariableUtilities.checkVariableConflict(newParams, p, p.getVariableStorage(), null);
			VariableUtilities.checkVariableConflict(locals, p, p.getVariableStorage(),
				localConflictHandler);
		}
	}

	protected static int findPointerParameterNamed(List<? extends Variable> params, String name) {
		for (int i = 0; i < params.size(); i++) {
			Variable p = params.get(i);
			if (!(p.getDataType() instanceof Pointer)) {
				continue;
			}
			if (!name.equals(p.getName())) {
				continue;
			}
			return i;
		}
		return -1;
	}

	protected static int findExplicitThisParameter(List<? extends Variable> params) {
		return findPointerParameterNamed(params, THIS_PARAM_NAME);
	}

	protected static boolean removeExplicitThisParameter(List<? extends Variable> params,
			String callingConventionName) {
		// TODO: Move this to VariableUtilities?
		// TODO: Factor the one from FunctionDB, too.
		if (!CompilerSpec.CALLING_CONVENTION_thiscall.equals(callingConventionName)) {
			return false;
		}
		int thisIndex = findExplicitThisParameter(params);
		if (thisIndex < 0) {
			return false;
		}
		params.remove(thisIndex);
		return true;
	}

	protected boolean doRemoveExplicitThisParameter() {
		if (!CompilerSpec.CALLING_CONVENTION_thiscall.equals(getCallingConventionName())) {
			return false;
		}
		int thisIndex = findExplicitThisParameter(params);
		if (thisIndex < 0) {
			return false;
		}
		removeParameter(thisIndex);
		return true;
	}

	protected static int findExplicitReturnStorageParameter(List<? extends Variable> params) {
		return findPointerParameterNamed(params, RETURN_PTR_PARAM_NAME);
	}

	protected static boolean removeExplicitReturnStorageParameter(List<? extends Variable> params) {
		int paramIndex = findExplicitReturnStorageParameter(params);
		if (paramIndex < 0) {
			return false;
		}
		params.remove(paramIndex);
		return true;
	}

	protected boolean doRemoveExplicitReturnStorageParameter() {
		int paramIndex = findExplicitReturnStorageParameter(params);
		if (paramIndex < 0) {
			return false;
		}
		removeParameter(paramIndex);
		return true;
	}

	protected static Variable revertIndirectParameter(Variable param, boolean create) {
		DataType dt = param.getDataType();
		if (!(dt instanceof Pointer)) {
			return param;
		}
		Pointer pdt = (Pointer) dt;
		try {
			if (create) {
				return new ParameterImpl(param.getName(), pdt.getDataType(), param.getProgram());
			}
			else {
				param.setDataType(pdt.getDataType(), VariableStorage.UNASSIGNED_STORAGE, false,
					param.getSource());
				return param;
			}
		}
		catch (InvalidInputException e) {
			throw new AssertionError(e);
		}
	}

	protected static DataType revertTypeIfIndirect(DataType dt, VariableStorage s) {
		if (!s.isForcedIndirect()) {
			return dt;
		}
		if (!(dt instanceof Pointer)) {
			return dt;
		}
		return ((Pointer) dt).getDataType();
	}

	protected static DataType getFormalDataTypeOf(Variable var) {
		if (var instanceof Parameter) {
			Parameter param = (Parameter) var;
			return param.getFormalDataType();
		}
		return var.getDataType();
	}

	protected static void assertNotUniqueSpace(Variable var) {
		if (!var.isUniqueVariable()) {
			return;
		}
		throw new IllegalArgumentException("Cannot use a unique-space variable");
	}

	@Override
	public void updateFunction(String callingConvention, Variable returnVar,
			List<? extends Variable> newParams, FunctionUpdateType updateType, boolean force,
			SourceType source) throws DuplicateNameException, InvalidInputException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.updateFunction(callingConvention, returnVar, newParams, updateType, force,
					source);
				return;
			}
			doLoadVariables();
			doPurgeBadVariables();

			boolean useCustomStorage = updateType == FunctionUpdateType.CUSTOM_STORAGE;
			setCustomVariableStorage(useCustomStorage);

			if (callingConvention != null) {
				setCallingConvention(callingConvention);
			}
			callingConvention = getCallingConventionName();

			if (returnVar == null) {
				returnVar = ret;
			}
			else if (returnVar == ret) {
				// Do nothing
			}
			else {
				returnVar.setName(Parameter.RETURN_NAME, returnVar.getSource());
				assertNotUniqueSpace(returnVar);
			}

			DataType returnType = returnVar.getDataType();
			VariableStorage returnStorage = returnVar.getVariableStorage();

			if (!useCustomStorage) {
				// remove auto params and forced-indirect return
				newParams = new ArrayList<>(newParams); // Going to edit
				boolean thisParamRemoved =
					removeExplicitThisParameter(newParams, callingConvention);
				if (removeExplicitReturnStorageParameter(newParams)) {
					returnVar = revertIndirectParameter(returnVar, true);
				}
				returnType = getFormalDataTypeOf(returnVar);
				returnStorage = VariableStorage.UNASSIGNED_STORAGE;

				if (updateType == FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS &&
					!thisParamRemoved &&
					CompilerSpec.CALLING_CONVENTION_thiscall.contentEquals(callingConvention) &&
					newParams.size() != 0) {
					// See FunctionDB's impl. It admits this is a hack.
					// It'd be nice if all this fixing up were in some utilities....
					Variable firstParam = newParams.get(0);
					if (firstParam.getSource() == SourceType.DEFAULT &&
						firstParam.getLength() == manager.dataTypeManager.getDataOrganization()
								.getPointerSize()) {
						newParams.remove(0);
					}
				}
			}

			// Update return data type
			getReturn().setDataType(returnType, returnStorage, true, source);

			Set<String> nonParamNames = new HashSet<>();
			for (DBTraceLabelSymbol s : manager.labels.getChildren(this)) {
				nonParamNames.add(s.getName());
			}
			for (DBTraceLocalVariableSymbol s : manager.localVars.getChildren(this)) {
				nonParamNames.add(s.getName());
			}

			// No conflicting names
			// Resolve all types
			List<Variable> resolvedParams = new ArrayList<>();
			for (Variable p : newParams) {
				if (!useCustomStorage && (p instanceof AutoParameterImpl)) {
					continue;
				}
				assertNotUniqueSpace(p);
				doCheckForParameterNameConflict(p, newParams, nonParamNames);
				resolvedParams.add(resolveVariable(p, false, !useCustomStorage));
			}
			newParams = resolvedParams;

			if (useCustomStorage) {
				doCheckStorageConflicts(newParams, force);
			}

			// Re-populate params list
			List<DBTraceParameterSymbol> oldParams = params;
			params = new ArrayList<>();

			// Clear current param names
			for (DBTraceParameterSymbol param : oldParams) {
				param.setName(null, SourceType.DEFAULT);
			}

			// Reassign old parameters if possible
			int newParamIndex = 0;
			for (; newParamIndex < oldParams.size() &&
				newParamIndex < newParams.size(); newParamIndex++) {
				DBTraceParameterSymbol oldParam = oldParams.get(newParamIndex);
				Variable newParam = newParams.get(newParamIndex);
				DataType dt = getFormalDataTypeOf(newParam);
				oldParam.setName(newParam.getName(), newParam.getSource());
				oldParam.doSetStorageAndDataType(newParam.getVariableStorage(), dt);
				oldParam.setComment(newParam.getComment());
				params.add(oldParam);
				manager.trace.setChanged(
					new TraceChangeRecord<>(TraceSymbolChangeType.CHANGED, getSpace(), oldParam));
			}
			// Remove unused old parameters
			for (int i = newParamIndex; i < oldParams.size(); i++) {
				oldParams.get(i).delete();
				// NOTE: Event produced by delete
			}
			// Append new parameters if needed
			for (int i = newParamIndex; i < newParams.size(); i++) {
				Variable newParam = newParams.get(i);
				DataType dt = getFormalDataTypeOf(newParam);
				VariableStorage storage = useCustomStorage ? newParam.getVariableStorage()
						: VariableStorage.UNASSIGNED_STORAGE;
				String newName = newParam.getName();
				if (newName == null || newName.length() == 0) {
					newName = SymbolUtilities.getDefaultParamName(i);
				}
				DBTraceParameterSymbol s = manager.parameterStore.create();
				s.set(newName, this, dt, storage, i, newParam.getSource());
				s.setComment(newParam.getComment());
				params.add(s);
				manager.trace.setChanged(
					new TraceChangeRecord<>(TraceSymbolChangeType.ADDED, getSpace(), s));
			}

			if (source.isHigherPriorityThan(signatureSource)) {
				signatureSource = source;
				update(SIGNATURE_SOURCE_COLUMN);
			}

			doUpdateParametersAndReturn();
		}
		finally {
			frame.invalidate();
		}
	}

	// NOTE: Must be called with the write lock
	protected void doDeleteVariable(AbstractDBTraceVariableSymbol var) {
		if (isBadVariable(var)) {
			return; // TODO: Investigate why
		}

		doLoadVariables();

		if (var instanceof DBTraceParameterSymbol) {
			if (params.remove(var)) {
				frame.invalidate();
				doUpdateParametersAndReturn();
			}
		}
		else {
			if (locals.remove(var)) {
				frame.invalidate();
			}
		}
	}

	@Override
	public void removeParameter(int ordinal) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.removeParameter(ordinal);
				return;
			}
			doLoadVariables();

			int index = ordinal;
			if (index < 0) {
				throw new IndexOutOfBoundsException(ordinal);
			}
			if (autoParams != null) {
				if (index < autoParams.size()) {
					// Cannot remove auto parameter. Ignore
					return;
				}
				index -= autoParams.size();
			}
			if (index >= params.size()) {
				throw new IndexOutOfBoundsException(ordinal);
			}
			params.get(ordinal).delete(); // Will call doDeleteVariable
		}
	}

	@Override
	public Parameter moveParameter(int fromOrdinal, int toOrdinal) throws InvalidInputException {
		if (toOrdinal < 0) {
			throw new InvalidInputException("destination ordinal cannot be negative");
		}
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				return thunked.moveParameter(fromOrdinal, toOrdinal);
			}
			doLoadVariables();

			if (fromOrdinal < 0) {
				return null;
			}
			int autoCnt = autoParams == null ? 0 : autoParams.size();
			if (fromOrdinal < autoCnt || toOrdinal < autoCnt) {
				throw new InvalidInputException(
					"Neither source nor destination ordinal can be within auto-parameters");
			}
			int fromIndex = fromOrdinal - autoCnt;
			int toIndex = toOrdinal - autoCnt;
			if (fromIndex > params.size()) {
				return null;
			}
			DBTraceParameterSymbol param = params.get(fromIndex);
			if (toIndex == fromIndex) {
				return param;
			}
			params.remove(fromIndex);
			if (toIndex >= params.size()) {
				params.add(param);
			}
			else {
				params.add(toIndex, param);
			}
			doUpdateParametersAndReturn();
			frame.invalidate();

			manager.trace.setChanged(new TraceChangeRecord<>(
				TraceFunctionChangeType.CHANGED_PARAMETERS, getSpace(), this));
			return param;
		}
	}

	@Override
	public DBTraceLocalVariableSymbol addLocalVariable(Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				return thunked.addLocalVariable(var, source);
			}
			doLoadVariables();
			doPurgeBadVariables();

			var = resolveVariable(var, false, false);

			VariableStorage storage = var.getVariableStorage();
			int firstUseOffset = var.getFirstUseOffset();
			if (var.hasStackStorage() && firstUseOffset != 0) {
				Msg.warn(this, "Stack variable first-use offset forced to 0 for function " + this +
					" at " + storage);
				firstUseOffset = 0;
			}

			String varName = var.getName();
			// NOTE null and 0-length checks are in isDefaultLocalName
			// NOTE: This is meant to be isDefaultParameterName
			// The parameter names are protected for all variables
			if (SymbolUtilities.isDefaultParameterName(varName)) {
				varName = DEFAULT_LOCAL_PREFIX;
				source = SourceType.DEFAULT;
			}

			// Check for duplicate storage address
			DBTraceLocalVariableSymbol lv = null;
			for (DBTraceLocalVariableSymbol oldLocal : locals) {
				if (oldLocal.getFirstUseOffset() == firstUseOffset &&
					oldLocal.getVariableStorage().intersects(storage)) {
					lv = oldLocal;
					break;
				}
			}

			try {
				// TODO: validate enabled?
				VariableUtilities.checkVariableConflict(this, (lv != null ? lv : var), storage,
					true);
				if (lv != null) {
					// Update existing local
					Msg.warn(this, "Adding overlapping local variable for function " + this +
						" at " + lv.getVariableStorage() + " - Modifying existing variable!");
					if (!DEFAULT_LOCAL_PREFIX.equals(name)) {
						lv.setName(varName, source);
					}
					lv.doSetStorageAndDataType(storage, var.getDataType());
				}
				else {
					// Create new local
					lv = manager.localVarStore.create();
					lv.set(varName, this, var.getDataType(), storage, firstUseOffset, source);
					locals.add(lv);
					locals.sort(VariableUtilities::compare);
				}
				if (var.getComment() != null) {
					lv.setComment(var.getComment());
				}
				return lv;
			}
			finally {
				frame.invalidate();
			}
		}
	}

	@Override
	public void removeVariable(Variable var) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.removeVariable(var);
				return;
			}
			doLoadVariables();

			if (!(var instanceof AbstractDBTraceVariableSymbol)) {
				return;
			}
			AbstractDBTraceVariableSymbol dbVar = (AbstractDBTraceVariableSymbol) var;
			if (params.contains(dbVar) || locals.contains(dbVar)) {
				dbVar.delete(); // Calls doDeleteVariable
			}
		}
	}

	@Override
	public Parameter getParameter(int ordinal) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getParameter(ordinal);
			}
			doLoadVariables();
			if (ordinal == Parameter.RETURN_ORIDINAL) {
				return ret;
			}
			if (autoParams != null) {
				if (ordinal < autoParams.size()) {
					return autoParams.get(ordinal);
				}
				ordinal -= autoParams.size();
			}
			if (ordinal < params.size()) {
				return params.get(ordinal);
			}
			return null;
		}
	}

	@Override
	public int getParameterCount() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getParameterCount();
			}
			doLoadVariables();
			if (autoParams != null) {
				return autoParams.size() + params.size();
			}
			return params.size();
		}
	}

	@Override
	public int getAutoParameterCount() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getAutoParameterCount();
			}
			doLoadVariables();
			if (autoParams != null) {
				return autoParams.size();
			}
			return 0;
		}
	}

	@Override
	public Parameter[] getParameters() {
		return getParameters(null);
	}

	protected <T extends Variable, U extends T> void collect(Collection<T> into, Collection<U> from,
			VariableFilter filter) {
		if (from == null) {
			return;
		}
		if (filter == null) {
			into.addAll(from);
		}
		else {
			into.addAll(Collections2.filter(from, filter::matches));
		}
	}

	@Override
	public Parameter[] getParameters(VariableFilter filter) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getParameters(filter);
			}
			doLoadVariables();
			List<Parameter> result = new ArrayList<>();
			collect(result, autoParams, filter);
			collect(result, params, filter);
			return result.toArray(new Parameter[result.size()]);
		}
	}

	@Override
	public TraceLocalVariableSymbol[] getLocalVariables() {
		return getLocalVariables(null);
	}

	@Override
	public TraceLocalVariableSymbol[] getLocalVariables(VariableFilter filter) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getLocalVariables(filter);
			}
			doLoadVariables();
			List<Variable> result = new ArrayList<>();
			collect(result, locals, filter);
			return result.toArray(new TraceLocalVariableSymbol[result.size()]);
		}
	}

	@Override
	public Variable[] getVariables(VariableFilter filter) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getParameters();
			}
			doLoadVariables();
			List<Variable> result = new ArrayList<>();
			collect(result, autoParams, filter);
			collect(result, params, filter);
			collect(result, locals, filter);
			return result.toArray(new Variable[result.size()]);
		}
	}

	@Override
	public Variable[] getAllVariables() {
		return getVariables(null);
	}

	@Override
	public void setBody(AddressSetView newBody) throws OverlappingFunctionException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			DBTraceFunctionSymbolView.assertProperSpace(entryPoint.getAddressSpace(), newBody);
			if (!newBody.contains(entryPoint)) {
				throw new IllegalArgumentException("Function body must contain the entry point");
			}
			AddressSetView oldBody = this.getBody();
			if (oldBody.equals(newBody)) {
				return;
			}
			manager.functions.assertNotOverlapping(this, getEntryPoint(), getLifespan(), newBody);
			for (DBTraceLabelSymbol label : manager.labels.getChildren(this)) {
				if (!newBody.contains(label.getAddress())) {
					label.delete();
				}
			}
			long id = getID();
			manager.delID(null, entryPoint.getAddressSpace(), id);
			for (AddressRange rng : newBody) {
				manager.putID(lifespan, null, rng, id);
			}
			manager.trace.setChanged(new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED_BODY,
				getSpace(), this, oldBody, newBody));
		}
	}

	protected byte getFlags() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (thunked != null) {
				return thunked.getFlags();
			}
			return flags;
		}
	}

	protected void orFlags(byte with) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.orFlags(with);
				return;
			}
			flags |= with;
			update(FLAGS_COLUMN);
		}
	}

	protected void andFlags(byte with) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.orFlags(with);
				return;
			}
			flags &= with;
			update(FLAGS_COLUMN);
		}
	}

	@Override
	public boolean hasVarArgs() {
		return (getFlags() & VAR_ARGS_MASK) != 0;
	}

	@Override
	public void setVarArgs(boolean hasVarArgs) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (hasVarArgs() == hasVarArgs) {
				return;
			}
			if (hasVarArgs) {
				orFlags(VAR_ARGS_MASK);
			}
			else {
				andFlags(VAR_ARGS_CLEAR);
			}
			manager.trace.setChanged(new TraceChangeRecord<>(
				TraceFunctionChangeType.CHANGED_PARAMETERS, getSpace(), this));
		}
	}

	@Override
	public boolean isInline() {
		return (getFlags() & INLINE_MASK) != 0;
	}

	@Override
	public void setInline(boolean isInline) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (isInline() == isInline) {
				return;
			}
			if (isInline) {
				orFlags(INLINE_MASK);
			}
			else {
				andFlags(INLINE_CLEAR);
			}
			manager.trace.setChanged(new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED_INLINE,
				getSpace(), this, !isInline, isInline));
		}
	}

	@Override
	public boolean hasNoReturn() {
		return (getFlags() & NO_RETURN_MASK) != 0;
	}

	@Override
	public void setNoReturn(boolean hasNoReturn) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (hasNoReturn() == hasNoReturn) {
				return;
			}
			if (hasNoReturn) {
				orFlags(NO_RETURN_MASK);
			}
			else {
				andFlags(NO_RETURN_CLEAR);
			}
			manager.trace.setChanged(
				new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED_NORETURN, getSpace(), this,
					!hasNoReturn, hasNoReturn));
		}
	}

	@Override
	public boolean hasCustomVariableStorage() {
		return (getFlags() & CUSTOM_STORAGE_MASK) != 0;
	}

	@Override
	public void setCustomVariableStorage(boolean hasCustomVariableStorage) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (hasCustomVariableStorage == hasCustomVariableStorage()) {
				return;
			}
			doLoadVariables();

			if (!hasCustomVariableStorage) {
				doRemoveExplicitThisParameter();
				if (doRemoveExplicitReturnStorageParameter()) {
					revertIndirectParameter(ret, false);
				}
			}

			// get params and return prior to change
			Parameter[] parameters = getParameters();
			HashMap<Parameter, VariableStorage> oldStorages = new HashMap<>(params.size());
			HashMap<Parameter, DataType> oldFormalTypes = new HashMap<>(params.size());
			for (Parameter p : parameters) {
				if (!p.isAutoParameter()) {
					oldStorages.put(p, p.getVariableStorage());
					if (hasCustomVariableStorage == false) {
						// Was custom
						oldFormalTypes.put(p,
							revertTypeIfIndirect(p.getFormalDataType(), p.getVariableStorage()));
					}
					else {
						oldFormalTypes.put(p, p.getFormalDataType());
					}
				}
			}

			VariableStorage oldRetStorage = ret.getVariableStorage();
			DataType oldRetType = ret.getFormalDataType();

			autoParams = null;
			if (hasCustomVariableStorage) {
				orFlags(CUSTOM_STORAGE_MASK);
			}
			else {
				andFlags(CUSTOM_STORAGE_CLEAR);
			}

			int ordinal = 0;
			for (Parameter p : parameters) {
				if (p.isAutoParameter()) {
					// NOTE: If changing from custom to dynamic, we should encounter no auto params
					try {
						insertParameter(ordinal, new ParameterImpl(p, getProgram()),
							SourceType.ANALYSIS);
						ordinal++;
					}
					catch (DuplicateNameException e) {
						Msg.info(this,
							"Clobbered auto-parameter during transition to custom storage");
						// Otherwise, skip
					}
				}
				else {
					DBTraceParameterSymbol dbP = (DBTraceParameterSymbol) p;
					VariableStorage oldStorage = oldStorages.get(p);
					VariableStorage newStorage =
						hasCustomVariableStorage ? oldStorage.clone(getProgram())
								: VariableStorage.UNASSIGNED_STORAGE;
					DataType newType = manager.checkIndirection(oldStorage, oldFormalTypes.get(p));
					dbP.doSetStorageAndDataType(newStorage, newType);
				}
			}

			VariableStorage newRetStorage =
				hasCustomVariableStorage ? oldRetStorage.clone(getProgram())
						: VariableStorage.UNASSIGNED_STORAGE;
			DataType newRetType = manager.checkIndirection(oldRetStorage, oldRetType);
			ret.doSetStorageAndDataType(newRetStorage, newRetType);

			if (!hasCustomVariableStorage) {
				doUpdateParametersAndReturn();
			}

			manager.trace.setChanged(new TraceChangeRecord<>(
				TraceFunctionChangeType.CHANGED_PARAMETERS, getSpace(), this));
		}
		catch (InvalidInputException e) {
			throw new AssertionError(e);
		}
		finally {
			frame.invalidate();
		}
	}

	@Override
	public PrototypeModel getCallingConvention() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			CompilerSpec cs = manager.trace.getBaseCompilerSpec();
			if (cs == null) {
				return null;
			}
			if (DBTraceSymbolManager.UNKNOWN_CALLING_CONVENTION_ID == callingConventionID) {
				return null;
			}
			if (DBTraceSymbolManager.DEFAULT_CALLING_CONVENTION_ID == callingConventionID) {
				return cs.getDefaultCallingConvention();
			}
			String ccName = manager.callingConventionMap.inverse().get(callingConventionID);
			if (ccName == null) {
				return null;
			}
			return cs.getCallingConvention(ccName);
		}
	}

	@Override
	public String getCallingConventionName() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (DBTraceSymbolManager.UNKNOWN_CALLING_CONVENTION_ID == callingConventionID) {
				return null;
			}
			if (DBTraceSymbolManager.DEFAULT_CALLING_CONVENTION_ID == callingConventionID) {
				return DBTraceSymbolManager.DEFAULT_CALLING_CONVENTION_NAME;
			}
			return manager.callingConventionMap.inverse().get(callingConventionID);
		}
	}

	@Override
	public String getDefaultCallingConventionName() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			PrototypeModel cc = manager.functions.getDefaultCallingConvention();
			if (cc == null) {
				return DBTraceSymbolManager.DEFAULT_CALLING_CONVENTION_NAME;
			}
			String ccName = cc.getName();
			if (ccName == null) { // Really?
				return DBTraceSymbolManager.DEFAULT_CALLING_CONVENTION_NAME;
			}
			return ccName;
		}
	}

	@Override
	public void setCallingConvention(String name) throws InvalidInputException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thunked != null) {
				thunked.setCallingConvention(name);
				return;
			}
			if (Objects.equals(getCallingConventionName(), name)) {
				return;
			}
			doLoadVariables();

			this.callingConventionID = manager.findOrRecordCallingConvention(name);
			update(CALLING_CONVENTION_COLUMN);

			boolean hasCustomStorage = hasCustomVariableStorage();
			if (!hasCustomStorage) {
				doRemoveExplicitThisParameter();
			}

			frame.invalidate();

			if (!hasCustomStorage) {
				createClassStructIfNeeded(); // TODO: Ditto from FunctionDB
				doLoadVariables(); // TODO: Why?
				doRemoveExplicitThisParameter(); // Again, why?
				doUpdateParametersAndReturn();
				manager.trace.setChanged(new TraceChangeRecord<>(
					TraceFunctionChangeType.CHANGED_PARAMETERS, getSpace(), this));
				manager.trace.setChanged(new TraceChangeRecord<>(
					TraceFunctionChangeType.CHANGED_RETURN, getSpace(), this));
			}
			else {
				manager.trace.setChanged(
					new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED, getSpace(), this));
			}
		}
	}

	protected void createClassStructIfNeeded() {
		PrototypeModel cc = getCallingConvention();
		if (cc == null || cc.getGenericCallingConvention() != GenericCallingConvention.thiscall) {
			return;
		}
		Namespace parentNS = getParentNamespace();
		if (!(parentNS instanceof GhidraClass)) {
			return;
		}

		DataTypeManager dtm = manager.dataTypeManager;
		DataType classStruct =
			VariableUtilities.findExistingClassStruct((GhidraClass) parentNS, dtm);
		if (classStruct == null) {
			// NOTE: Check for existence first, to avoid resolving unnecessarily.
			// TODO: If ever struct-class are strongly related, fix that here, too.
			classStruct = VariableUtilities.findOrCreateClassStruct((GhidraClass) parentNS, dtm);
			dtm.resolve(classStruct, null);
		}
	}

	@Override
	public boolean isThunk() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return thunked != null;
		}
	}

	@Override
	public DBTraceFunctionSymbol getThunkedFunction(boolean recursive) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (recursive) {
				if (thunked != null) {
					return thunked.getThunkedFunction(recursive);
				}
				return this;
			}
			return thunked;
		}
	}

	@Override
	public Address[] getFunctionThunkAddresses() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			List<Address> result = new ArrayList<>();
			for (DBTraceFunctionSymbol thunk : manager.functionsByThunked.get(getKey())) {
				result.add(thunk.entryPoint);
			}
			return result.toArray(new Address[result.size()]);
		}
	}

	@Override
	public void setThunkedFunction(Function thunkedFunction) throws IllegalArgumentException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			DBTraceFunctionSymbol dbFunc = manager.assertIsMine(thunkedFunction);
			if (getThunkedFunction(true) == dbFunc) {
				throw new IllegalArgumentException("Cannot create circle of thunks");
			}
			if (this.thunkedKey == dbFunc.getKey()) {
				return;
			}
			TraceFunctionSymbol oldThunk = thunked;
			this.thunkedKey = dbFunc.getKey();
			update(THUNKED_COLUMN);
			this.thunked = dbFunc;
			manager.trace.setChanged(new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED_THUNK,
				getSpace(), this, oldThunk, dbFunc));
		}
	}

	@Override
	public ExternalLocation getExternalLocation() {
		return null;
	}

	@Override
	public Set<Function> getCallingFunctions(TaskMonitor monitor) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Set<Function> result = new HashSet<>();
			for (DBTraceReference ref : manager.trace.getReferenceManager()
					.getReferencesToRange(
						lifespan, new AddressRangeImpl(entryPoint, entryPoint))) {
				if (monitor.isCancelled()) {
					break;
				}
				Address fromAddr = ref.getFromAddress();
				Range<Long> span = lifespan.intersection(ref.getLifespan());
				/**
				 * NOTE: Could be zero, one, or more (because lifespans may be staggered).
				 * Logically, at the actual call time of any given call at most one function is
				 * present. However, it caller could be invoked under different conditions at
				 * different times, so abstractly, we still consider multiple a reasonable result.
				 */
				result.addAll(manager.functions.getIntersecting(span, getThread(),
					new AddressRangeImpl(fromAddr, fromAddr), true, true));
			}
			return result;
		}
	}

	@Override
	public Set<Function> getCalledFunctions(TaskMonitor monitor) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Set<Function> result = new HashSet<>();
			for (AddressRange rng : getBody()) {
				for (DBTraceReference ref : manager.trace.getReferenceManager()
						.getReferencesFromRange(
							lifespan, rng)) {
					if (monitor.isCancelled()) {
						return result;
					}
					Address toAddr = ref.getToAddress();
					Range<Long> span = lifespan.intersection(ref.getLifespan());
					/**
					 * NOTE: Could be zero, one, or more (because lifespans may be staggered).
					 * Logically, at the actual call time of any given call at most one function is
					 * present. However, it caller could be invoked under different conditions at
					 * different times, so abstractly, we still consider multiple a reasonable
					 * result.
					 */
					for (DBTraceFunctionSymbol function : manager.functions.getIntersecting(span,
						getThread(), new AddressRangeImpl(toAddr, toAddr), true, true)) {
						if (toAddr.equals(function.getEntryPoint())) {
							result.add(function);
						}
					}
				}
			}
			return result;
		}
	}

	@Override
	public void promoteLocalUserLabelsToGlobal() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			List<DBTraceLabelSymbol> toPromote =
				new ArrayList<>(Collections2.filter(manager.labels().getChildren(this),
					l -> l.getSource() == SourceType.USER_DEFINED));
			for (DBTraceLabelSymbol label : toPromote) {
				try {
					label.setNamespace(manager.getGlobalNamespace());
				}
				catch (DuplicateNameException e) {
					label.delete();
				}
				catch (InvalidInputException | CircularDependencyException e) {
					throw new AssertionError(e);
				}
			}
		}
	}

	@Override
	public boolean delete() {
		// TODO: Prevent spurious update logic as the parameters/locals are all deleted
		boolean result = super.delete();
		SourceType source = getSource();
		if (result && source != SourceType.DEFAULT) {
			try {
				manager.labels.add(lifespan, null, entryPoint, name, parent, source);
			}
			catch (InvalidInputException | IllegalArgumentException e) {
				throw new AssertionError(e); // The fields have already been validated.
			}
		}
		return result;
	}

	protected void setReturnAddressOffset(int offset) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			this.stackReturnOffset = offset;
			update(STACK_RETURN_OFFSET_COLUMN);
		}
		manager.trace.setChanged(
			new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED, getSpace(), this));
	}

	protected int getReturnAddressOffset() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return stackReturnOffset;
		}
	}
}
