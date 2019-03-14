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
package ghidra.app.plugin;

public interface PluginCategoryNames {
	String COMMON = GenericPluginCategoryNames.COMMON;
	String SUPPORT = GenericPluginCategoryNames.SUPPORT;
	String CODE_VIEWER = "Code Viewer";
	String BYTE_VIEWER = "Byte Viewer";
	String GRAPH = "Graph";
	String ANALYSIS = "Analysis";
	String NAVIGATION = "Navigation";
	String SEARCH = "Search";
	String TREE = "Program Tree";
	String TESTING = GenericPluginCategoryNames.TESTING;
	String DIFF = "Code Difference";
	String MISC = GenericPluginCategoryNames.MISC;
	String USER_ANNOTATION = "User Annotation";
	String EXAMPLES = GenericPluginCategoryNames.EXAMPLES;
	String SELECTION = "Selection";
	String INTERPRETERS = "Interpreters";
	String DEBUGGER = "Debugger";
	String PATCHING = "Patching";
	String DECOMPILER = "Decompiler";
	String UNMANAGED = "Unmanaged";
}
