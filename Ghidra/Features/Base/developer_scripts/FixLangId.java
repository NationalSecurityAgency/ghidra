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
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;

import db.*;
import db.buffers.BufferFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.ImproperUseException;
import ghidra.framework.data.GhidraFile;
import ghidra.framework.data.GhidraFileData;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.FolderItem;
import ghidra.framework.store.local.LocalDatabaseItem;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class FixLangId extends GhidraScript {

	private static final String LANGUAGE_ID = "Language ID";
	private static final String LANGUAGE_VERSION = "Language Version";
	private static final String TABLE_NAME = "Program";

	@Override
	public void run() throws Exception {

		DomainFile df = askProgramFile("Select Program File");
		if (df == null) {
			return;
		}
		if (df.isVersioned()) {
			Msg.showError(getClass(), null, "Script Error",
				"Selected project file must not be under version control!");
			return;
		}

		GhidraFile gf = (GhidraFile) df;

		Method method = GhidraFile.class.getDeclaredMethod("getFileData", new Class<?>[0]);
		method.setAccessible(true);

		GhidraFileData fileData = (GhidraFileData) method.invoke(gf, new Object[0]);

		FolderItem item = (FolderItem) getInstanceField("folderItem", fileData);
		if (!(item instanceof LocalDatabaseItem)) {
			Msg.showError(getClass(), null, "Script Error", "Unsupported file type!");
			return;
		}
		LocalDatabaseItem dbItem = (LocalDatabaseItem) item;
		BufferFile bf = dbItem.openForUpdate(-1);
		DBHandle dbh = new DBHandle(bf);
		if (!modifyLanguage(df, dbh)) {
			dbh.close();
			return;
		}

		dbh.save("Set Language", null, TaskMonitorAdapter.DUMMY_MONITOR);
		dbh.close();
	}

	private boolean modifyLanguage(DomainFile df, DBHandle dbh)
			throws IOException, ImproperUseException {

		// TODO: Check for address map and overlay entries which could break from
		// changing the memory model !!

		Table table = dbh.getTable(TABLE_NAME);
		if (table == null) {
			Msg.showError(getClass(), null, "Script Error", "Bad program database!!");
			return false;
		}
		DBRecord record = table.getRecord(new StringField(LANGUAGE_ID));
		if (record == null) {  // must be in old style combined language/compiler spec format
			Msg.showError(getClass(), null, "Script Error",
				"Old program file!  Language fix is not appropriate.");
			return false;
		}
		String langId = record.getString(0);
		LanguageDescription desc = null;
		List<LanguageDescription> descriptions =
			DefaultLanguageService.getLanguageService().getLanguageDescriptions(true);
		List<String> choices = new ArrayList<>(descriptions.size());
		for (int i = 0; i < descriptions.size(); i++) {
			choices.add(descriptions.get(i).getLanguageID().getIdAsString());
		}

		try {
			langId = askChoice("Select New Language", "Language ID:", choices, null);
			if (langId != null) {
				Msg.warn(this, "Changing language ID from '" + record.getString(0) + "' to '" +
					langId + "' for program: " + df.getName());
				desc = DefaultLanguageService.getLanguageService().getLanguageDescription(
					new LanguageID(langId));
				long txId = dbh.startTransaction();
				try {
					record.setString(0, langId);
					table.putRecord(record);
					record = table.getSchema().createRecord(new StringField(LANGUAGE_VERSION));
					record.setString(0, desc.getVersion() + "." + desc.getMinorVersion());
					table.putRecord(record);
				}
				finally {
					dbh.endTransaction(txId, true);
				}
				return true;
			}
		}
		catch (CancelledException e) {
			// just return false
		}
		return false;
	}

	public DomainFile askProgramFile(String title) {
		final DomainFile[] domainFile = new DomainFile[] { null };
		final DataTreeDialog dtd = new DataTreeDialog(null, title, DataTreeDialog.OPEN);
		dtd.addOkActionListener(e -> {
			dtd.close();
			domainFile[0] = dtd.getDomainFile();
		});
		try {
			SwingUtilities.invokeAndWait(() -> dtd.showComponent());
		}
		catch (Exception e) {
			return null;
		}
		if (domainFile[0] != null &&
			!Program.class.isAssignableFrom(domainFile[0].getDomainObjectClass())) {
			Msg.showError(getClass(), null, "Script Error",
				"Selected project file is not a program file!");
			return null;
		}
		return domainFile[0];
	}

	public static Object getInstanceField(String fieldName, Object ownerInstance)
			throws RuntimeException {

		if (ownerInstance == null) {
			throw new NullPointerException("Owner of instance field cannot be null");
		}

		Class<?> objectClass =
			(ownerInstance instanceof Class) ? (Class<?>) ownerInstance : ownerInstance.getClass();
		Object result = null;
		try {
			// get the field from the class object 
			Field field = locateFieldObjectOnClass(fieldName, objectClass);

			// open up the field so that we have access
			field.setAccessible(true);

			// get the field from the object instance that we were provided
			result = field.get(ownerInstance);
		}
		catch (Exception e) {
			throw new RuntimeException("Unable to use reflection to obtain " + "field: " +
				fieldName + " from class: " + objectClass, e);
		}

		return result;
	}

	public static Field locateFieldObjectOnClass(String fieldName, Class<?> containingClass) {
		Field field = null;

		try {
			field = containingClass.getDeclaredField(fieldName);
		}
		catch (NoSuchFieldException nsfe) {
			// O.K., the field may be located on a parent class.  So, we
			// will call this method on the parent class
			Class<?> parentClass = containingClass.getSuperclass();

			if (parentClass != null) {
				field = locateFieldObjectOnClass(fieldName, parentClass);
			}
		}

		return field;
	}
}
