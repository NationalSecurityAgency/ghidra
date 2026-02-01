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
package sarif.export.props;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.model.util.VoidPropertyMap;
import ghidra.util.SaveableColor;
import ghidra.util.SaveablePoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.PropertiesSarifMgr;

public class SarifPropertyMapWriter extends AbstractExtWriter {

	List<PropertyMap<?>> maps;
	Program program;
	AddressSetView set;

	public SarifPropertyMapWriter(List<PropertyMap<?>> request, Program program, AddressSetView set, Writer baseWriter)
			throws IOException {
		super(baseWriter);
		this.maps = request;
		this.program = program;
		this.set = set;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genMap(monitor);
		root.add("properties", objects);
	}

	private void genMap(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.initialize(maps.size());
		for (PropertyMap<?> map : maps) {
			if (map instanceof VoidPropertyMap) {
				genVoidMap((VoidPropertyMap) map, monitor);
			} else if (map instanceof IntPropertyMap) {
				genIntMap((IntPropertyMap) map, monitor);
			} else if (map instanceof LongPropertyMap) {
				genLongMap((LongPropertyMap) map, monitor);
			} else if (map instanceof StringPropertyMap) {
				genStringMap((StringPropertyMap) map, monitor);
			} else if (map instanceof ObjectPropertyMap) {
				genObjectMap((ObjectPropertyMap<?>) map, monitor);
			}
		}
	}

	private void genVoidMap(VoidPropertyMap map, TaskMonitor monitor) throws CancelledException {
		AddressIterator iter = set != null ? map.getPropertyIterator(set) : map.getPropertyIterator();
		while (iter.hasNext()) {
			Address addr = iter.next();
			ExtProperty isf = new ExtProperty(map.getName(), "void", null);
			SarifObject sarif = new SarifObject(PropertiesSarifMgr.SUBKEY, PropertiesSarifMgr.KEY, getTree(isf), addr,
					addr);
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}

	private void genIntMap(IntPropertyMap map, TaskMonitor monitor) throws CancelledException {
		AddressIterator iter = set != null ? map.getPropertyIterator(set) : map.getPropertyIterator();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			try {
				Address addr = iter.next();
				int value = map.getInt(addr);
				ExtProperty isf = new ExtProperty(map.getName(), "int", Integer.toHexString(value));
				SarifObject sarif = new SarifObject(PropertiesSarifMgr.SUBKEY, PropertiesSarifMgr.KEY, getTree(isf),
						addr, addr);
				objects.add(getTree(sarif));
			} catch (NoValueException e) {
				// skip
			}
		}
	}

	private void genLongMap(LongPropertyMap map, TaskMonitor monitor) throws CancelledException {
		AddressIterator iter = set != null ? map.getPropertyIterator(set) : map.getPropertyIterator();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			try {
				Address addr = iter.next();
				long value = map.getLong(addr);
				ExtProperty isf = new ExtProperty(map.getName(), "long", Long.toHexString(value));
				SarifObject sarif = new SarifObject(PropertiesSarifMgr.SUBKEY, PropertiesSarifMgr.KEY, getTree(isf),
						addr, addr);
				objects.add(getTree(sarif));
			} catch (NoValueException e) {
				// skip
			}
		}

	}

	private void genStringMap(StringPropertyMap map, TaskMonitor monitor) throws CancelledException {
		AddressIterator iter = set != null ? map.getPropertyIterator(set) : map.getPropertyIterator();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Address addr = iter.next();
			String value = map.getString(addr);
			ExtProperty isf = new ExtProperty(map.getName(), "string", value);
			SarifObject sarif = new SarifObject(PropertiesSarifMgr.SUBKEY, PropertiesSarifMgr.KEY, getTree(isf), addr,
					addr);
			objects.add(getTree(sarif));
		}
	}
	

	private void genObjectMap(ObjectPropertyMap<?> map, TaskMonitor monitor) throws CancelledException {
		AddressIterator iter = set != null ? map.getPropertyIterator(set) : map.getPropertyIterator();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Address addr = iter.next();
			Object value = map.get(addr);
			ExtProperty isf;
			if (value instanceof SaveablePoint) {
				isf = new ExtProperty(map.getName(), "point", value.toString());
			}
			else if (value instanceof SaveableColor) {
				isf = new ExtProperty(map.getName(), "color", value.toString());
			}
			else {
				return;
			}
			SarifObject sarif = new SarifObject(PropertiesSarifMgr.SUBKEY, PropertiesSarifMgr.KEY, getTree(isf), addr,
					addr);
			objects.add(getTree(sarif));
		}
	}

}
