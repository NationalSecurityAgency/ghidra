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
package ghidra.program.database.data;

import java.io.IOException;
import java.util.*;

import db.Record;
import ghidra.docking.settings.Settings;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.UniversalID;

class FunctionDefinitionDB extends DataTypeDB implements FunctionDefinition {

	private FunctionDefinitionDBAdapter funDefAdapter;
	private FunctionParameterAdapter paramAdapter;
	private ArrayList<ParameterDefinitionDB> parameters;

	FunctionDefinitionDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			FunctionDefinitionDBAdapter adapter, FunctionParameterAdapter paramAdapter,
			Record record) {
		super(dataMgr, cache, record);
		this.funDefAdapter = adapter;
		this.paramAdapter = paramAdapter;
		getParameters();
	}

	@Override
	protected String doGetName() {
		return record.getString(FunctionDefinitionDBAdapter.FUNCTION_DEF_NAME_COL);
	}

	@Override
	protected long doGetCategoryID() {
		return record.getLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_CAT_ID_COL);
	}

	private void getParameters() {
		parameters = new ArrayList<>();
		try {
			long[] ids = paramAdapter.getParameterIdsInFunctionDef(key);
			for (long id : ids) {
				Record rec = paramAdapter.getRecord(id);
				parameters.add(new ParameterDefinitionDB(dataMgr, paramAdapter, this, rec));
			}
			Collections.sort(parameters);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	protected boolean refresh() {
		try {
			Record rec = funDefAdapter.getRecord(key);
			if (rec != null) {
				record = rec;
				getParameters();
				return super.refresh();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.data.DataType#isDynamicallySized()
	 */
	@Override
	public boolean isDynamicallySized() {
		return false;
	}

	@Override
	public String getPrototypeString() {
		return getPrototypeString(false);
	}

	@Override
	public String getPrototypeString(boolean includeCallingConvention) {
		lock.acquire();
		try {
			checkIsValid();
			StringBuffer buf = new StringBuffer();
			DataType returnType = getReturnType();
			buf.append((returnType != null ? returnType.getDisplayName() : "void"));
			buf.append(" ");
			if (includeCallingConvention) {
				GenericCallingConvention genericCallingConvention = getGenericCallingConvention();
				if (genericCallingConvention != GenericCallingConvention.unknown) {
					buf.append(genericCallingConvention.name());
					buf.append(" ");
				}
			}
			buf.append(getName());
			buf.append("(");
			boolean hasVarArgs = hasVarArgs();
			int n = parameters.size();
			for (int i = 0; i < n; i++) {
				ParameterDefinition param = parameters.get(i);
				buf.append(param.getDataType().getDisplayName());
				buf.append(" ");
				buf.append(param.getName());
				if ((i < (n - 1)) || hasVarArgs) {
					buf.append(", ");
				}
			}
			if (hasVarArgs) {
				buf.append(VAR_ARGS_DISPLAY_STRING);
			}
			else if (parameters.size() == 0) {
				buf.append(VOID_PARAM_DISPLAY_STRING);
			}
			buf.append(")");

			return buf.toString();
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.FunctionSignature#getArguments()
	 */
	@Override
	public ParameterDefinition[] getArguments() {
		lock.acquire();
		try {
			ParameterDefinition[] vars = new ParameterDefinition[parameters.size()];
			return parameters.toArray(vars);
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.FunctionSignature#getReturnType()
	 */
	@Override
	public DataType getReturnType() {
		lock.acquire();
		try {
			checkIsValid();
			long dtId = record.getLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_RETURN_ID_COL);
			DataType dt = dataMgr.getDataType(dtId);
			if (dt == null) {
				dt = DataType.VOID;
			}
			return dt;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof FunctionDefinition)) {
			throw new IllegalArgumentException();
		}
		doReplaceWith((FunctionDefinition) dataType);
	}

	private void doReplaceWith(FunctionDefinition functionDefinition) {
		setArguments(functionDefinition.getArguments());
		setReturnType(functionDefinition.getReturnType());
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.FunctionSignature#getComment()
	 */
	@Override
	public String getComment() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getString(FunctionDefinitionDBAdapter.FUNCTION_DEF_COMMENT_COL);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return new FunctionDefinitionDataType(getCategoryPath(), getName(), this, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		return new FunctionDefinitionDataType(getCategoryPath(), getName(), this, getUniversalID(),
			getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getMnemonic(ghidra.program.model.data.Settings)
	 */
	@Override
	public String getMnemonic(Settings settings) {
		return getPrototypeString();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public int getLength() {
		return -1;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Function Signature Data Type";
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return getPrototypeString();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.FunctionDefinition#setArguments(ghidra.program.model.listing.Variable[])
	 */
	@Override
	public void setArguments(ParameterDefinition[] args) {
		lock.acquire();
		try {
			checkDeleted();
			Iterator<ParameterDefinitionDB> it = parameters.iterator();
			while (it.hasNext()) {
				ParameterDefinitionDB param = it.next();
				param.getDataType().removeParent(this);
				paramAdapter.removeRecord(param.getKey());
			}
			parameters.clear();
			for (int i = 0; i < args.length; i++) {
				DataType resolvedDt = resolve(args[i].getDataType());
				paramAdapter.createRecord(dataMgr.getID(resolvedDt), key, i, args[i].getName(),
					args[i].getComment(), args[i].getLength());
			}
			getParameters();
			it = parameters.iterator();
			while (it.hasNext()) {
				ParameterDefinitionDB param = it.next();
				param.getDataType().addParent(this);
			}
			funDefAdapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.FunctionDefinition#setReturnType(ghidra.program.model.data.DataType)
	 */
	@Override
	public void setReturnType(DataType type) {
		lock.acquire();
		try {
			checkDeleted();
			getReturnType().removeParent(this);
			if (type == null) {
				type = DataType.VOID;
			}
			DataType resolvedDt = resolve(type);
			record.setLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_RETURN_ID_COL,
				dataMgr.getID(resolvedDt));
			funDefAdapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this);
			resolvedDt.addParent(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.FunctionDefinition#setComment(java.lang.String)
	 */
	@Override
	public void setComment(String comment) {
		lock.acquire();
		try {
			checkDeleted();
			record.setString(FunctionDefinitionDBAdapter.FUNCTION_DEF_COMMENT_COL, comment);
			funDefAdapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeDeleted(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeDeleted(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			int n = parameters.size();
			for (int i = 0; i < n; i++) {
				ParameterDefinitionDB param = parameters.get(i);
				if (param.getDataType() == dt) {
					dt.removeParent(this);
					param.setDataType(DataType.DEFAULT);
				}
			}
			if (dt == getReturnType()) {
				dt.removeParent(this);
				setReturnType(DataType.VOID);
			}
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#isEquivalent(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (!(dt instanceof FunctionDefinition)) {
			return false;
		}

		checkIsValid();
		if (resolving) {
			if (dt.getUniversalID().equals(getUniversalID())) {
				return true;
			}
			return DataTypeUtilities.equalsIgnoreConflict(getPathName(), dt.getPathName());
		}
		return isEquivalentSignature((FunctionSignature) dt);
	}

	@Override
	public boolean isEquivalentSignature(FunctionSignature signature) {
		if (signature == this) {
			return true;
		}
		String comment = signature.getComment();
		String myComment = getComment();
		if ((DataTypeUtilities.equalsIgnoreConflict(signature.getName(), getName())) &&
			((comment == null && myComment == null) ||
				(comment != null && comment.equals(myComment))) &&
			(DataTypeUtilities.isSameOrEquivalentDataType(signature.getReturnType(),
				getReturnType())) &&
			(getGenericCallingConvention() == signature.getGenericCallingConvention()) &&
			(hasVarArgs() == signature.hasVarArgs())) {
			ParameterDefinition[] args = signature.getArguments();
			ParameterDefinition[] thisArgs = this.getArguments();
			if (args.length == thisArgs.length) {
				for (int i = 0; i < args.length; i++) {
					if (!args[i].isEquivalent(thisArgs[i])) {
						return false;
					}
				}
				return true;
			}
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.data.DataType#setCategoryPath(ghidra.program.model.data.CategoryPath)
	 */
	@Override
	protected void doSetCategoryPathRecord(long categoryID) throws IOException {
		record.setLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_CAT_ID_COL, categoryID);
		funDefAdapter.updateRecord(record, false);
	}

	/**
	 * @see ghidra.program.model.data.DataType#setName(java.lang.String)
	 */
	@Override
	protected void doSetNameRecord(String name) throws IOException {
		record.setString(FunctionDefinitionDBAdapter.FUNCTION_DEF_NAME_COL, name);
		funDefAdapter.updateRecord(record, true);
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeReplaced(ghidra.program.model.data.DataType, ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		lock.acquire();
		try {
			checkDeleted();
			if (newDt == this) {
				newDt = DataType.DEFAULT;
			}
			DataType retType = getReturnType();
			if (oldDt == retType) {
				setReturnType(newDt);
			}
			int n = parameters.size();
			for (int i = 0; i < n; i++) {
				ParameterDefinitionDB param = parameters.get(i);
				if (param.getDataType() == oldDt) {
					oldDt.removeParent(this);
					param.setDataType(newDt);
					newDt.addParent(this);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void replaceArgument(int ordinal, String name, DataType dt, String comment,
			SourceType source) {
//TODO:
		if (dt.getLength() <= 0) {
			throw new IllegalArgumentException("Fixed length data type expected");
		}
		lock.acquire();
		try {
			checkDeleted();
			if (ordinal >= parameters.size()) {
				for (int i = parameters.size(); i < ordinal; i++) {
					paramAdapter.createRecord(dataMgr.getResolvedID(DataType.DEFAULT), key, i,
						Function.DEFAULT_PARAM_PREFIX + (i + 1), null, 1);
				}
			}
			else {
				ParameterDefinitionDB param = parameters.get(ordinal);
				param.getDataType().removeParent(this);
				paramAdapter.removeRecord(param.getKey());
			}
			DataType rdt = resolve(dt);
			rdt.addParent(this);
			paramAdapter.createRecord(dataMgr.getID(rdt), key, ordinal, name, comment,
				dt.getLength());
			getParameters();
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeNameChanged(ghidra.program.model.data.DataType, java.lang.String)
	 */
	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// don't care
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.FunctionSignature#hasVarArgs()
	 */
	@Override
	public boolean hasVarArgs() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return false;
			}
			byte flags = record.getByteValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_FLAGS_COL);
			return ((flags & FunctionDefinitionDBAdapter.FUNCTION_DEF_VARARG_FLAG) != 0);
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.FunctionDefinition#setVarArgs(boolean)
	 */
	@Override
	public void setVarArgs(boolean hasVarArgs) {
		lock.acquire();
		try {
			checkDeleted();
			byte flags = record.getByteValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_FLAGS_COL);
			if (hasVarArgs) {
				flags |= FunctionDefinitionDBAdapter.FUNCTION_DEF_VARARG_FLAG;
			}
			else {
				flags &= ~FunctionDefinitionDBAdapter.FUNCTION_DEF_VARARG_FLAG;
			}
			record.setByteValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_FLAGS_COL, flags);
			try {
				funDefAdapter.updateRecord(record, true);
				dataMgr.dataTypeChanged(this);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.FunctionDefinition#setGenericCallingConvention(ghidra.program.model.data.GenericCallingConvention)
	 */
	@Override
	public void setGenericCallingConvention(GenericCallingConvention genericCallingConvention) {
		lock.acquire();
		try {
			checkDeleted();
			int ordinal = genericCallingConvention.ordinal();
			if (ordinal < 0 ||
				ordinal > FunctionDefinitionDBAdapter.GENERIC_CALLING_CONVENTION_FLAG_MASK) {
				Msg.error(this, "GenericCallingConvention ordinal unsupported: " + ordinal);
				return;
			}
			byte flags = record.getByteValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_FLAGS_COL);
			flags &=
				~(FunctionDefinitionDBAdapter.GENERIC_CALLING_CONVENTION_FLAG_MASK << FunctionDefinitionDBAdapter.GENERIC_CALLING_CONVENTION_FLAG_SHIFT);
			flags |= ordinal << FunctionDefinitionDBAdapter.GENERIC_CALLING_CONVENTION_FLAG_SHIFT;
			record.setByteValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_FLAGS_COL, flags);
			try {
				funDefAdapter.updateRecord(record, true);
				dataMgr.dataTypeChanged(this);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.FunctionSignature#getGenericCallingConvention()
	 */
	@Override
	public GenericCallingConvention getGenericCallingConvention() {
		lock.acquire();
		try {
			checkIsValid();
			if (record == null) {
				return GenericCallingConvention.unknown;
			}
			byte flags = record.getByteValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_FLAGS_COL);
			int ordinal =
				(flags >> FunctionDefinitionDBAdapter.GENERIC_CALLING_CONVENTION_FLAG_SHIFT) &
					FunctionDefinitionDBAdapter.GENERIC_CALLING_CONVENTION_FLAG_MASK;
			return GenericCallingConvention.get(ordinal);
		}
		finally {
			lock.release();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getLastChangeTime()
	 */
	@Override
	public long getLastChangeTime() {
		return record.getLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_LAST_CHANGE_TIME_COL);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getSourceSyncTime()
	 */
	@Override
	public long getLastChangeTimeInSourceArchive() {
		return record.getLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_SOURCE_SYNC_TIME_COL);
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_LAST_CHANGE_TIME_COL,
				lastChangeTime);
			funDefAdapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTime) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_SOURCE_SYNC_TIME_COL,
				lastChangeTime);
			funDefAdapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public UniversalID getUniversalID() {
		return new UniversalID(
			record.getLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_SOURCE_DT_ID_COL));
	}

	@Override
	protected void setUniversalID(UniversalID id) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_SOURCE_DT_ID_COL,
				id.getValue());
			funDefAdapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	protected UniversalID getSourceArchiveID() {
		return new UniversalID(
			record.getLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL));
	}

	@Override
	protected void setSourceArchiveID(UniversalID id) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL,
				id.getValue());
			funDefAdapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}
}
