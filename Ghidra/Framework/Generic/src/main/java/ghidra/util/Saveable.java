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
package ghidra.util;


/**
 * 
 * Save and restore elements that are compatible with ObjectStorage objects.
 * <br>
 * <p><b>Important</b>: Any class implementing this interface that
 * may have its class path saved to the data base (i.e. user defined properties)
 * should create a map in the <code>ClassTranslator</code> when it is moved 
 * or renamed between versions of Ghidra. It should also implement <code>ExtensionPoint</code>.
 * <br><p>For example, any class that implements the <code>Saveable</code> interface 
 * can potentially be saved as a property in the program. If used as a program 
 * property the class name gets saved to a database field in the property manager. 
 * If the class gets moved or renamed, the property manager won't be able to 
 * instantiate it. The <code>ClassTranslator</code> allows the saveable class 
 * to indicate its old path name (that was stored in the database) and its
 * current path name (the actual location of the class it needs to instantiate 
 * for the property). 
 * <br>The saveable class should call 
 * <br><code>    ClassTranslator.put(oldClassPath, newClassPath);</code>
 * <br>in its static initializer.
 * <br>The property manager would then call 
 * <br><code>    String newPathName = ClassTranslator.get(oldPathName);</code> 
 * <br>when it can't find the class for the old path name. 
 * If the new path name isn't null the property manager can use it to get the class.
 * 
 * 
 */
public interface Saveable {
	
    /**
     * Returns the field classes, in Java types, in the same order as used {@link #save} and
     * {@link #restore}. 
     * <p>
     * For example, if the save method calls <code>objStorage.putInt()</code> and then
     * <code>objStorage.putFloat()</code>, then this method must return 
     * <code>Class[]{ Integer.class, Float.class }</code>. 
     * @return
     */
    Class<?>[] getObjectStorageFields();
    
	/**
	 * Save to the given ObjectStorage.
	 * @param objStorage Object that can handle Java primitives, Strings, and
	 * arrays of primitives and Strings
	 */
	void save(ObjectStorage objStorage);
	
	/**
	 * Restore from the given ObjectStorage.
	 * @param objStorage Object that can handle Java primitives, Strings, and
	 * arrays of primitives and Strings
	 * @throws db.IllegalFieldAccessException
	 * if objStorage is improperly accessed.
	 */
	void restore(ObjectStorage objStorage);
	
	/**
	 * Get the storage schema version.  Any time there is a software release
	 * in which the implementing class has changed the data structure used 
	 * for the save and restore methods, the schema version must be incremented.
	 * NOTE: While this could be a static method, the Saveable interface is unable to 
	 * define such methods.
	 * @return storage schema version.
	 */
	int getSchemaVersion();
	
	/**
	 * Determine if the implementation supports an storage upgrade of the specified
	 * oldSchemaVersion to the current schema version.
	 * @param oldSchemaVersion 
	 * @return true if upgrading is supported for the older schema version.
	 */
	boolean isUpgradeable(int oldSchemaVersion);
	
	/**
	 * Upgrade an older stored object to the current storage schema. 
	 * @param oldObjStorage the old stored object
	 * @param oldSchemaVersion storage schema version number for the old object
	 * @param currentObjStorage new object for storage in the current schema
	 * @return true if data was upgraded to the currentObjStorage successfully.
	 */
	boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage);

	/**
	 * Returns true if this saveable should not have it's changes broadcast.
	 * @return true if this saveable should not have it's changes broadcast.
	 */
	boolean isPrivate();
}
