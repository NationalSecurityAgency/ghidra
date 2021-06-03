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
package ghidra.framework.data;

import java.beans.PropertyEditor;
import java.io.IOException;
import java.util.*;

import db.*;
import ghidra.framework.options.*;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.ClosedException;

/**
 * Database implementation of {@link Option}
 */
class OptionsDB extends AbstractOptions {

	private static final String PROPERTY_TABLE_NAME = "Property Table";

	private final static Schema PROPERTY_SCHEMA = new Schema(0, StringField.INSTANCE,
		"Property Name", new Field[] { StringField.INSTANCE, ByteField.INSTANCE },
		new String[] { "Value", "Type" });

	private static final int VALUE_COL = 0;
	private static final int TYPE_COL = 1;

	private Table propertyTable;
	private DomainObjectAdapterDB domainObj;

	OptionsDB(DomainObjectAdapterDB domainObj) {
		super("");
		this.domainObj = domainObj;
		propertyTable = domainObj.getDBHandle().getTable(PROPERTY_TABLE_NAME);
	}

	/**
	 * Perform property alterations as specified by the map provided.  This must be called
	 * immediately following construction before any other instance method is invoked 
	 * (with the exception of checkAlterations)
	 * @param propertyAlterations oldPath-to-newPath property mappings.  Paths must not end
	 * with the '.' path separator. If the newPath is null or conflicts with an existing stored property,
	 * the corresponding oldPath properties will be removed.
	 * @throws IllegalStateException if list has been manipulated since construction
	 * @throws IllegalArgumentException if invalid property alterations are provided
	 * @throws IOException if there is an exception moving or deleting a property 
	 */
	synchronized void performAlterations(Map<String, String> propertyAlterations)
			throws IOException {
		if (propertyAlterations == null) {
			return;
		}
		if (!super.getOptionNames().isEmpty()) {
			throw new IllegalStateException("property list alterations not permitted");
		}
		for (String oldPath : propertyAlterations.keySet()) {
			checkAlterationPath(oldPath, false);
			String newPath = propertyAlterations.get(oldPath);
			checkAlterationPath(newPath, true);
			if (newPath == null || !moveProperties(oldPath, newPath)) {
				removeProperties(oldPath);
			}
		}
	}

	private void checkAlterationPath(String path, boolean nullIsOK) {
		if (!nullIsOK && path == null) {
			throw new IllegalArgumentException("property alteration old-path may not be null");
		}
		if (path != null && path.endsWith(DELIMITER_STRING)) {
			throw new IllegalArgumentException(
				"property alteration paths must not end with '" + DELIMITER + "': " + path);
		}
	}

	private synchronized boolean moveProperties(String oldPath, String newPath) throws IOException {

		String oldSubListPath = oldPath + ".";
		String newSubListPath = newPath + ".";

		// check for move conflict
		if (propertyTable.getRecord(new StringField(newPath)) != null) {
			return false;
		}
		RecordIterator iterator = propertyTable.iterator(new StringField(newSubListPath));
		DBRecord rec = iterator.next();
		if (rec != null) {
			String keyName = ((StringField) rec.getKeyField()).getString();
			if (keyName.startsWith(newSubListPath)) {
				return false;
			}
		}

		// move records
		ArrayList<DBRecord> list = new ArrayList<>();
		rec = propertyTable.getRecord(new StringField(oldPath));
		if (rec != null) {
			propertyTable.deleteRecord(new StringField(oldPath));
			rec.setKey(new StringField(newPath));
			list.add(rec);
		}
		iterator = propertyTable.iterator(new StringField(oldSubListPath));
		while (iterator.hasNext()) {
			rec = iterator.next();
			String keyName = ((StringField) rec.getKeyField()).getString();
			if (keyName.startsWith(oldSubListPath)) {
				iterator.delete();
				rec.setKey(
					new StringField(newSubListPath + keyName.substring(oldSubListPath.length())));
				list.add(rec);
			}
			else {
				break;
			}
		}
		for (DBRecord updatedRec : list) {
			propertyTable.putRecord(updatedRec);
		}

		return true;
	}

	private synchronized void removeProperties(String path) throws IOException {

		String subListPath = path + ".";

		// remove records
		RecordIterator iterator = propertyTable.iterator(new StringField(path));
		while (iterator.hasNext()) {
			DBRecord rec = iterator.next();
			String keyName = ((StringField) rec.getKeyField()).getString();
			if (keyName.equals(path)) {
				iterator.delete();
			}
			else if (keyName.startsWith(subListPath)) {
				iterator.delete();
			}
		}

	}

	@Override
	public synchronized void removeOption(String propertyName) {
		super.removeOption(propertyName);
		removePropertyFromDB(propertyName);
		// NOTE: AbstractOptions does not provide removal notification
		notifyOptionChanged(propertyName, null, null);
	}

	private void removePropertyFromDB(String propertyName) {
		try {
			StringField key = new StringField(propertyName);
			if (propertyTable.hasRecord(key)) {
				propertyTable.deleteRecord(key);
			}
		}
		catch (IOException e) {
			domainObj.dbError(e);
		}
	}

	synchronized void clearCache() {
		for (Option option : valueMap.values()) {
			DBOption dbOption = (DBOption) option;
			dbOption.clearCache();
		}
	}

	@Override
	public synchronized List<String> getOptionNames() {
		Set<String> names = new HashSet<>(valueMap.keySet());
		names.addAll(aliasMap.keySet());
		try {
			if (propertyTable != null) {
				RecordIterator recIt = propertyTable.iterator();
				while (recIt.hasNext()) {
					DBRecord rec = recIt.next();
					names.add(rec.getKeyField().getString());
				}
			}
		}
		catch (IOException e) {
			domainObj.dbError(e);
		}
		List<String> optionNames = new ArrayList<>(names);
		Collections.sort(optionNames);
		return optionNames;
	}

	@Override
	public synchronized boolean contains(String optionName) {
		if (super.contains(optionName)) {
			return true;
		}
		try {
			if (propertyTable != null) {
				RecordIterator recIt = propertyTable.iterator();
				while (recIt.hasNext()) {
					DBRecord rec = recIt.next();
					String key = rec.getKeyField().getString();
					if (optionName.equals(key)) {
						return true;
					}
				}
			}
		}
		catch (IOException e) {
			domainObj.dbError(e);
		}
		return false;
	}

	private DBRecord getPropertyRecord(String propertyName) {
		if (propertyTable == null) {
			return null;
		}
		try {
			return propertyTable.getRecord(new StringField(propertyName));
		}
		catch (ClosedException e) {
			return null; // ignore closed file
		}
		catch (IOException e) {
			domainObj.dbError(e);
		}
		return null;
	}

	private void putRecord(DBRecord rec) {
		try {
			if (propertyTable == null) {
				propertyTable =
					domainObj.getDBHandle().createTable(PROPERTY_TABLE_NAME, PROPERTY_SCHEMA);
			}
			propertyTable.putRecord(rec);
		}
		catch (IOException e) {
			domainObj.dbError(e);
		}
	}

	class DBOption extends Option {
		private Object value = null;
		private boolean isCached = false;

		protected DBOption(String name, OptionType type, String description, HelpLocation help,
				Object defaultValue, boolean isRegistered, PropertyEditor editor) {
			super(name, type, description, help, defaultValue, isRegistered, editor);

			getCurrentValue(); // initialize our defaults
		}

		@Override
		public Object getCurrentValue() {
			if (!isCached) {
				DBRecord rec = getPropertyRecord(getName());
				if (rec == null) {
					value = getDefaultValue();
				}
				else {
					OptionType optionType = OptionType.values()[rec.getByteValue(TYPE_COL)];

					// Make sure the optionType in the database matches the current
					// registered type.  If not, it implies the option type has been changed
					// in the code. In that case, ignore the old value.
					if (optionType == getOptionType()) {
						value = optionType.convertStringToObject(rec.getString(VALUE_COL));
					}
				}
			}
			isCached = true;
			return value;
		}

		@Override
		public void doSetCurrentValue(Object newValue) {
			if (SystemUtilities.isEqual(getCurrentValue(), newValue)) {
				return;
			}
			this.value = newValue;
			this.isCached = true;
			if (SystemUtilities.isEqual(newValue, getDefaultValue())) { // changing back to default value
				removePropertyFromDB(getName());
			}
			else {
				DBRecord rec = PROPERTY_SCHEMA.createRecord(new StringField(getName()));
				OptionType optionType = getOptionType();
				rec.setByteValue(TYPE_COL, (byte) (optionType.ordinal()));
				rec.setString(VALUE_COL, optionType.convertObjectToString(newValue));
				putRecord(rec);
			}
		}

		void clearCache() {
			value = null;
			isCached = false;
		}

	}

	@Override
	protected Option createRegisteredOption(String optionName, OptionType type, String description,
			HelpLocation help, Object defaultValue, PropertyEditor editor) {
		return new DBOption(optionName, type, description, help, defaultValue, true, editor);
	}

	@Override
	protected Option createUnregisteredOption(String optionName, OptionType type,
			Object defaultValue) {

		if (type == OptionType.NO_TYPE) {
			DBRecord record = getPropertyRecord(optionName);
			if (record != null) {
				type = OptionType.values()[record.getByteValue(TYPE_COL)];
			}
		}
		return new DBOption(optionName, type, null, null, defaultValue, false, null);
	}

	@Override
	protected boolean notifyOptionChanged(String optionName, Object oldValue, Object newValue) {
		return domainObj.propertyChanged(optionName, oldValue, newValue);
	}

}
