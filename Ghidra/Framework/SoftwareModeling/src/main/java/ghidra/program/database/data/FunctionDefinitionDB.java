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

import db.DBRecord;
import db.Field;
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
			DBRecord record) {
		super(dataMgr, cache, record);
		this.funDefAdapter = adapter;
		this.paramAdapter = paramAdapter;
		loadParameters();
	}

	@Override
	protected String doGetName() {
		return record.getString(FunctionDefinitionDBAdapter.FUNCTION_DEF_NAME_COL);
	}

	@Override
	protected long doGetCategoryID() {
		return record.getLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_CAT_ID_COL);
	}

	private void loadParameters() {
		parameters = new ArrayList<>();
		try {
			Field[] ids = paramAdapter.getParameterIdsInFunctionDef(key);
			for (Field id : ids) {
				DBRecord rec = paramAdapter.getRecord(id.getLongValue());
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
			DBRecord rec = funDefAdapter.getRecord(key);
			if (rec != null) {
				record = rec;
				loadParameters();
				return super.refresh();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return false;
	}

	@Override
	public boolean hasLanguageDependantLength() {
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

	@Override
	public DataType getReturnType() {
		lock.acquire();
		try {
			checkIsValid();
			long dtId = record.getLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_RETURN_ID_COL);
			DataType dt = dataMgr.getDataType(dtId);
			if (dt == null) {
				dt = DataType.DEFAULT;
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

		lock.acquire();
		try {
			checkDeleted();

			setArguments(functionDefinition.getArguments());
			try {
				setReturnType(functionDefinition.getReturnType());
			}
			catch (IllegalArgumentException e) {
				setReturnType(DEFAULT);
			}
			setVarArgs(functionDefinition.hasVarArgs());
			setGenericCallingConvention(functionDefinition.getGenericCallingConvention());
		}
		finally {
			lock.release();
		}
	}

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

	@Override
	public String getMnemonic(Settings settings) {
		return getPrototypeString();
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public String getDescription() {
		return "Function Signature Data Type";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return getPrototypeString();
	}

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
				DataType type =
					ParameterDefinitionImpl.validateDataType(args[i].getDataType(), dataMgr, false);
				DataType resolvedDt = resolve(type);
				paramAdapter.createRecord(dataMgr.getID(resolvedDt), key, i, args[i].getName(),
					args[i].getComment(), args[i].getLength());
				resolvedDt.addParent(this);
			}
			loadParameters();
			funDefAdapter.updateRecord(record, true); // update last change time
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setReturnType(DataType type) {
		type = ParameterDefinitionImpl.validateDataType(type, dataMgr, true);
		lock.acquire();
		try {
			checkDeleted();
			getReturnType().removeParent(this);
			if (type == null) {
				type = DataType.DEFAULT;
			}
			DataType resolvedDt = resolve(type);
			record.setLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_RETURN_ID_COL,
				dataMgr.getID(resolvedDt));
			funDefAdapter.updateRecord(record, true);
			resolvedDt.addParent(this);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setComment(String comment) {
		lock.acquire();
		try {
			checkDeleted();
			record.setString(FunctionDefinitionDBAdapter.FUNCTION_DEF_COMMENT_COL, comment);
			funDefAdapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			int n = parameters.size();
			for (int i = 0; i < n; i++) {
				ParameterDefinitionDB param = parameters.get(i);
				if (param.getDataType() == dt) {
					param.setDataType(DataType.DEFAULT);
				}
			}
			if (dt == getReturnType()) {
				setReturnType(DataType.DEFAULT);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isEquivalent(DataType dataType) {

		if (dataType == this) {
			return true;
		}
		if (!(dataType instanceof FunctionDefinition)) {
			return false;
		}

		checkIsValid();
		if (resolving) { // actively resolving children
			if (dataType.getUniversalID().equals(getUniversalID())) {
				return true;
			}
			return DataTypeUtilities.equalsIgnoreConflict(getPathName(), dataType.getPathName());
		}

		Boolean isEquivalent = dataMgr.getCachedEquivalence(this, dataType);
		if (isEquivalent != null) {
			return isEquivalent;
		}

		try {
			isEquivalent = isEquivalentSignature((FunctionSignature) dataType);
		}
		finally {
			dataMgr.putCachedEquivalence(this, dataType, isEquivalent);
		}
		return isEquivalent;
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
			(DataTypeUtilities.isSameOrEquivalentDataType(getReturnType(),
				signature.getReturnType())) &&
			(getGenericCallingConvention() == signature.getGenericCallingConvention()) &&
			(hasVarArgs() == signature.hasVarArgs())) {
			ParameterDefinition[] args = signature.getArguments();
			ParameterDefinition[] thisArgs = this.getArguments();
			if (args.length == thisArgs.length) {
				for (int i = 0; i < args.length; i++) {
					if (!thisArgs[i].isEquivalent(args[i])) {
						return false;
					}
				}
				return true;
			}
		}
		return false;
	}

	@Override
	protected void doSetCategoryPathRecord(long categoryID) throws IOException {
		record.setLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_CAT_ID_COL, categoryID);
		funDefAdapter.updateRecord(record, false);
	}

	@Override
	protected void doSetNameRecord(String name) throws IOException {
		record.setString(FunctionDefinitionDBAdapter.FUNCTION_DEF_NAME_COL, name);
		funDefAdapter.updateRecord(record, true);
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		lock.acquire();
		try {
			checkDeleted();
			if (newDt == this) {
				// avoid creating circular dependency
				newDt = DataType.DEFAULT;
			}
			DataType retType = getReturnType();
			if (oldDt == retType) {
				try {
					setReturnType(newDt);
				}
				catch (IllegalArgumentException e) {
					// oldDt replaced with incompatible type - treat as removal
					dataTypeDeleted(oldDt);
					return;
				}
			}
			int n = parameters.size();
			for (int i = 0; i < n; i++) {
				ParameterDefinitionDB param = parameters.get(i);
				if (param.getDataType() == oldDt) {
					try {
						param.setDataType(newDt);
					}
					catch (IllegalArgumentException e) {
						// oldDt replaced with incompatible type - treat as removal
						dataTypeDeleted(oldDt);
						return;
					}
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
			loadParameters();
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// don't care
	}

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
				dataMgr.dataTypeChanged(this, false);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

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
				dataMgr.dataTypeChanged(this, false);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

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

	@Override
	public long getLastChangeTime() {
		return record.getLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_LAST_CHANGE_TIME_COL);
	}

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
			dataMgr.dataTypeChanged(this, false);
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
			dataMgr.dataTypeChanged(this, false);
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
			dataMgr.dataTypeChanged(this, false);
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
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String toString() {
		return getPrototypeString(true);
	}
}
