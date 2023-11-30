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
package sarif.export.ref;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.ShiftedReference;
import ghidra.program.model.symbol.StackReference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.export.extlib.ExtLibraryLocation;
import sarif.managers.ExternalLibSarifMgr;
import sarif.managers.MarkupSarifMgr;

public class SarifReferenceWriter extends AbstractExtWriter {
	
	private List<Address> references = new ArrayList<>();
	private ReferenceManager referenceManager;

	public SarifReferenceWriter(ReferenceManager referenceManager, List<Address> request, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.referenceManager = referenceManager;
		this.references = request;
	}

	public void requestFunction(Address next) {
		references.add(next);
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genReferences(monitor);
		root.add("references", objects);
	}

	private void genReferences(TaskMonitor monitor) throws CancelledException, IOException{
		monitor.initialize(references.size());
		for (Address addr : references) {
			Reference[] refs = referenceManager.getReferencesFrom(addr);
			for (int i = 0; i < refs.length; i++) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				Reference ref = refs[i];
				if (ref.isRegisterReference()) {
					ExtRegisterReference mref = new ExtRegisterReference(ref);
					SarifObject sarif = new SarifObject("Ref.Register", MarkupSarifMgr.KEY, getTree(mref), ref.getFromAddress(), ref.getFromAddress());
					objects.add(getTree(sarif));
				}
				if (ref.isMemoryReference()) {
					ExtMemoryReference mref = new ExtMemoryReference(ref);
					SarifObject sarif = new SarifObject("Ref.Memory", MarkupSarifMgr.KEY, getTree(mref), ref.getFromAddress(), ref.getFromAddress());
					objects.add(getTree(sarif));
				}
				if (ref.isStackReference()) {
					ExtStackReference sref = new ExtStackReference((StackReference) ref);
					SarifObject sarif = new SarifObject("Ref.Stack", MarkupSarifMgr.KEY, getTree(sref), ref.getFromAddress(), ref.getFromAddress());
					objects.add(getTree(sarif));
				}
				if (ref.isShiftedReference()) {
					ExtShiftedReference sref = new ExtShiftedReference((ShiftedReference) ref);
					SarifObject sarif = new SarifObject("Ref.Shifted", MarkupSarifMgr.KEY, getTree(sref), ref.getFromAddress(), ref.getFromAddress());
					objects.add(getTree(sarif));
				}
				if (ref.isExternalReference()) {
					ExternalReference extRef = (ExternalReference) ref;
					
					// OK, this is overkill, but some of these locations are not written by
					// either the SarifClassesNamspaceWriter or the SarifExternalLibraryWriter
					ExternalLocation extLoc = extRef.getExternalLocation();
					ExtLibraryLocation obj = new ExtLibraryLocation(extLoc);
					SarifObject sarif0 = new SarifObject(ExternalLibSarifMgr.SUBKEY1, ExternalLibSarifMgr.KEY, getTree(obj),
							extLoc.getAddress(), extLoc.getAddress());
					objects.add(getTree(sarif0));
					
					ExtExternalReference xref = new ExtExternalReference(extRef);
					SarifObject sarif = new SarifObject("Ref.External", MarkupSarifMgr.KEY, getTree(xref), ref.getFromAddress(), ref.getFromAddress());
					objects.add(getTree(sarif));
				}
			}
			monitor.increment();
		}
	}
	
	public JsonArray getResults() {
		return objects;
	}

}
