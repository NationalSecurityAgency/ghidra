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
package ghidra.util.classfinder;

import java.util.Hashtable;

/**
 * <code>ClassTranslator</code> provides a way to map an old Ghidra class to
 * a current Ghidra class. It can be used whenever a class is moved or renamed
 * and Ghidra needs to know.
 * <p><strong>Important</strong>: Any class that is indicated by the currentClassPath
 * passed to the <code>put</code> method should implement <code>ExtensionPoint</code>.
 * <p>Whenever a class whose name gets stored in the data base is moved to 
 * another package or renamed, the map of the old class path name to the 
 * new one should get put into the ClassTranslator.
 * <br>Example:  The class <code>ghidra.app.plugin.core.MyPlugin.MyInfo</code> is in Ghidra version 1.
 * In Ghidra version 2, it is moved and renamed to <code>ghidra.app.plugin.core.RenamedPlugin.SubPackage.SaveInfo</code>.
 * Put the following static initializer in the version 2 SaveInfo class.
 * <br><code>
 *   static {
 *       ClassTranslator.put("ghidra.app.plugin.core.MyPlugin.MyInfo", SaveInfo.class.getName());
 *   }
 * </code>
 * <p>Warning: If the class gets moved or renamed again in a subsequent version 
 * of Ghidra, a new translation (put call) should get added to the static initializer block 
 * and any old translations should have their current path name changed to the new
 * class path.
 * <br>Example: The class <code>ghidra.app.plugin.core.MyPlugin.MyInfo</code> is in Ghidra version 1.
 * In Ghidra version 2, it is moved and renamed to <code>ghidra.app.plugin.core.RenamedPlugin.SubPackage.SaveInfo</code>.
 * In Ghidra version 3, it is renamed to <code>ghidra.app.plugin.core.RenamedPlugin.SubPackage.SaveInfo</code>.
 * Put the following static initializer in the version 3 SaveInfo class.
 * <code>
 *   static {
 *       ClassTranslator.put("ghidra.app.plugin.core.MyPlugin.MyInfo", SaveInfo.class.getName());
 *       ClassTranslator.put("ghidra.app.plugin.core.RenamedPlugin.SubPackage.SaveInfo", SaveInfo.class.getName());
 *   }
 * </code>
 */
public class ClassTranslator {
	private static Hashtable<String, String> classPathMap = new Hashtable<>();

	/**
	 * Returns true if this ClassTranslator has a mapping for the indicated old class path name.
	 * @param oldClassPath the old class path name of the class.
	 * @return true if the old class path is mapped to a new class path name in
	 * the current Ghidra version.
	 */
	public static boolean contains(String oldClassPath) {
		return classPathMap.containsKey(oldClassPath);
	}
	
	/**
	 * Returns the current class path name that is mapped for the indicated old class path name.
	 * @param oldClassPath the old class path name of the class.
	 * @return the class path name of the current Ghidra version's class file. Otherwise, null if the old class path name isn't mapped.
	 */
	public static String get(String oldClassPath) {
		return classPathMap.get(oldClassPath);
	}
	
	/**
	 * Defines a mapping indicating the class path name of the current Ghidra class 
	 * that is the same class as the indicated old class path name from a previous Ghidra version.
	 * @param oldClassPath the old class path name of the class.
	 * @param currentClassPath the current class path name of the class.
	 * <p><strong>Important</strong>: Any class that is indicated by the currentClassPath
	 * passed to the <code>put</code> method should implement <code>ExtensionPoint</code>.
	 */
	public static void put(String oldClassPath, String currentClassPath) {
		classPathMap.put(oldClassPath, currentClassPath);
	}
	
}
