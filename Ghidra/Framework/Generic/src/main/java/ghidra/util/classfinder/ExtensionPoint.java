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

/**
 * NOTE: ExtensionPoint logistics have changed! It is no longer sufficient to
 * implement ExtensionPoint in order for the ClassSearcher to dynamically pick
 * up your class. Your class also needs to conform to a class name suffix rule.
 * The modules included in your application can have a file named
 * "{ModuleRoot}/data/ExtensionPoint.manifest". This file contains (one per
 * line) the suffixes that should be checked for inclusion into the class
 * searching. IF YOUR EXTENSION POINT DOES NOT HAVE A SUFFIX INDICATED IN ONE OF
 * THESE FILES, IT WILL NOT BE AUTOMATICALLY DISCOVERED.
 * 
 * This is a marker interface used to mark classes and interfaces that Ghidra
 * will automatically search for and load.
 */
public interface ExtensionPoint {
	// Marker interface
}
