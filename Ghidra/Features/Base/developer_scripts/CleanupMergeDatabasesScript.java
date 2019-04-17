/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.app.script.GhidraScript;
import ghidra.framework.data.ProjectFileManager;
import ghidra.framework.model.Project;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.framework.store.local.LocalFolderItem;

import java.io.IOException;
import java.lang.reflect.Method;

public class CleanupMergeDatabasesScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		Project project = state.getProject();

		ProjectFileManager fileMgr = (ProjectFileManager) project.getProjectData();
		LocalFileSystem fs = (LocalFileSystem) fileMgr.getPrivateFileSystem();

		int cnt = cleanupFolder(fs, "/");

		if (cnt == 0) {
			popup("No merge databases found");
		}
		else {
			popup("Removed " + cnt + " merge databases");
		}
	}

	private String getPath(String folderPath, String name) {
		String path = FileSystem.SEPARATOR + name;
		if (!FileSystem.SEPARATOR.equals(folderPath)) {
			path = folderPath + path;
		}
		return path;
	}

	private int cleanupFolder(LocalFileSystem fs, String folderPath) throws IOException {

		int cnt = 0;

		for (String subfolderName : fs.getFolderNames(folderPath)) {
			cnt += cleanupFolder(fs, getPath(folderPath, subfolderName));
		}

		// fs.getItemNames(folderPath, true)
		String[] itemNames =
			(String[]) invokeInstanceMethod("getItemNames", fs, new Class[] { String.class,
				boolean.class }, new Object[] { folderPath, true });

		for (String itemName : itemNames) {
			if (!itemName.startsWith(LocalFileSystem.HIDDEN_ITEM_PREFIX)) {
				continue;
			}
			println("Removing temp file: " + getPath(folderPath, itemName));
			LocalFolderItem item = fs.getItem(folderPath, itemName);
			if (item != null) {
				// item.deleteContent();
				invokeInstanceMethod("deleteContent", item, null, null);
			}
			else {
				// make sure we get item out of index
				//fs.deallocateItemStorage(folderPath, itemName);
				invokeInstanceMethod("deallocateItemStorage", fs, new Class[] { String.class,
					String.class }, new Object[] { folderPath, itemName });
			}
			++cnt;
		}

		return cnt;
	}

	private static Object invokeInstanceMethod(String methodName, Object ownerInstance,
			Class<?>[] parameterTypes, Object[] args) throws RuntimeException {
		if (ownerInstance == null) {
			throw new NullPointerException("Owner of instance field cannot be null");
		}

		Class<?> objectClass =
			(ownerInstance instanceof Class) ? (Class<?>) ownerInstance : ownerInstance.getClass();
		Object result = null;

		try {

			// get the method object to call
			Method method = locateMethodObjectOnClass(methodName, objectClass, parameterTypes);

			if (method == null) {
				throw new NoSuchMethodException("Unable to find a method by " + "the name \"" +
					methodName + "\" on the class " + objectClass + " or any of its parent " +
					"implementations.");
			}

			// make sure we have access
			method.setAccessible(true);

			// execute the method and get the result
			result = method.invoke(ownerInstance, args);
		}
		catch (Exception e) {
			throw new RuntimeException("Unable to use reflection to call " + "method: " +
				methodName + " from class: " + objectClass, e);
		}

		return result;
	}

	private static Method locateMethodObjectOnClass(String methodName, Class<?> containingClass,
			Class<?>[] parameterTypes) {
		Method method = null;

		try {
			// if we get an exception here, then the current class does not
			// declare the method, but its parent may
			method = containingClass.getDeclaredMethod(methodName, parameterTypes);
		}
		catch (NoSuchMethodException nsme) {
			// O.K., the method may be located on a parent class.  So, we
			// will call this method on the parent class
			Class<?> parentClass = containingClass.getSuperclass();

			if (parentClass != null) {
				method = locateMethodObjectOnClass(methodName, parentClass, parameterTypes);
			}
		}

		return method;
	}

}
