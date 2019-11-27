/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the &quot;License&quot;);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an &quot;AS IS&quot; BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.xtext.sleigh.validation

	

import java.util.HashMap
import java.util.HashSet
import org.eclipse.xtext.validation.Check
import ghidra.xtext.sleigh.sleigh.Model
import ghidra.xtext.sleigh.sleigh.SleighPackage
import ghidra.xtext.sleigh.sleigh.VARSYM
import ghidra.xtext.sleigh.sleigh.constraint
import ghidra.xtext.sleigh.sleigh.contextdef
import ghidra.xtext.sleigh.sleigh.contextfielddef
import ghidra.xtext.sleigh.sleigh.fielddef
import ghidra.xtext.sleigh.sleigh.tokendef
import ghidra.xtext.sleigh.sleigh.vardef
import ghidra.xtext.sleigh.sleigh.varnodedef

import static extension org.eclipse.emf.ecore.util.EcoreUtil.*
import static extension org.eclipse.xtext.EcoreUtil2.*

/**
 * This class contains custom validation rules. 
 *
 * See https://www.eclipse.org/Xtext/documentation/303_runtime_concepts.html#validation
 */
class SleighValidator extends AbstractSleighValidator {

	var HashMap<Object,HashMap<String,HashSet<Object>>> typeMap;
	
    @Check
    def void checkModelInitialize(Model m) {
    	// model should be validated each time before the sub objects
    	// are validated, so initialize the cache
    	typeMap = new HashMap();
    }

	/**
	 * Add a name entry to the set of names->definitions Object map
	 */    
    def addNameEntryToSet(HashMap<String, HashSet<Object>> map, String name, Object other) {
		var HashSet<Object> set = map.get(name);
		if (set == null) {
			set = new HashSet<Object>();
			map.put(name,set);
		}
		set.add(other)
	}

	@Check
	def void checkTokenNameIsUnique(fielddef f) {
		if (checkDuplicate(f)) {
			warning("token field names have to be unique", SleighPackage.eINSTANCE.getfielddef_Name);
			return;
		}
	}
	
	def boolean checkDuplicate(fielddef f) {
		var type = typeof(tokendef)
		var HashMap<String,HashSet<Object>> map = typeMap.get(type);
		if (map == null) {
			map = new HashMap<String,HashSet<Object>>();
			typeMap.put(type,map);
			var defList = f.getRootContainer(true).getAllContentsOfType(type)
			var iter = defList.iterator;
			while (iter.hasNext()) {
				var def = iter.next();
				var fiter = def.getAllContentsOfType(typeof(fielddef)).iterator;
				while (fiter.hasNext()) {
					var other = fiter.next();
					var name = other.getName();
					addNameEntryToSet(map, name, other);
				}
			}
		}
		var HashSet<Object> set = map.get(f.name);
		return (set != null && set.size > 1)
	}
	
	@Check
	def void checkTokenNameIsUnique(contextfielddef f) {
		if (checkDuplicate(f)) {
			warning("context field names have to be unique", SleighPackage.eINSTANCE.getcontextfielddef_Name);
			return;
		}
	}
	
	def boolean checkDuplicate(contextfielddef f) {
		var type = typeof(contextdef)
		var HashMap<String,HashSet<Object>> map = typeMap.get(type);
		// if map hasn't been initialized, initialize it
		if (map == null) {
			map = new HashMap<String,HashSet<Object>>()
			typeMap.put(type,map)
			var defList = f.getRootContainer(true).getAllContentsOfType(type)
			var iter = defList.iterator
			while (iter.hasNext()) {
				var def = iter.next()
				var fiter = def.getAllContentsOfType(typeof(contextfielddef)).iterator
				while (fiter.hasNext()) {
					var other = fiter.next()
					var name = other.getName()
					addNameEntryToSet(map, name, other)
				}
			}
		}
		var HashSet<Object> set = map.get(f.name);
		return (set != null && set.size > 1)
	}	

	@Check
	def void checkTokenNameIsUnique(VARSYM v) {
		if (checkDuplicate(v)) {
			warning("var names have to be unique", SleighPackage.eINSTANCE.VARSYM_Name);
			return;
		}
	}
	
	def boolean checkDuplicate(VARSYM v) {
		var type = typeof(varnodedef)
		var HashMap<String,HashSet<Object>> map = typeMap.get(type);
		if (map == null) {
			map = new HashMap<String,HashSet<Object>>();
			typeMap.put(type,map);
			var defList = v.getRootContainer(true).getAllContentsOfType(type)
			var iter = defList.iterator;
			while (iter.hasNext()) {
				var def = iter.next();
				var fiter = def.getAllContentsOfType(typeof(vardef)).iterator;
				while (fiter.hasNext()) {
					var other = fiter.next();
					var name = other.varname.name;
					addNameEntryToSet(map, name, other);
				}
			}
		}
		var HashSet<Object> set = map.get(v.name);
		return (set != null && set.size > 1)
	}
	
	@Check
	def void checkWarnExpensiveOperation(constraint c) {
		var op = c.compareOp
		if (op == null || op.equals('=')) {
			return;
		}
		// TODO: Could check if the op token size is small, don't warn
		//     For token sizes, this should not be so expensive 2,3
		
		// comparison operations can be expensive
		warning("comparison can be expensive, and should be used sparingly", SleighPackage.eINSTANCE.getconstraint_CompareOp)
	}
}

