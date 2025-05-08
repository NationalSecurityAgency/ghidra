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
package ghidra.app.plugin.core.decompiler.taint;

import java.util.*;

import com.contrastsecurity.sarif.LogicalLocation;
import com.contrastsecurity.sarif.Run;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import sarif.SarifUtils;

public record TaintQueryResult(String name,String fqname, Address iaddr, Address faddr, List<String> labels, boolean functionLevelResult) {

	// NB: The constructors that follow depend on data generated at different phases in the processing.
	//   At first blush, it seems obvious that you could combine then by using the location data, accessed
	//   in the first to derive the LogicalLocation via llocs in SarifUtils.  llocs, however, is likely to
	//   be stale when applying the SARIF results.
	
	public TaintQueryResult(Map<String, Object> result) {
		this((String) result.get("name"), 
			(String) result.get("location"),
			(Address) result.get("Address"),
			(Address) result.get("entry"),
			new ArrayList<String>(),
			(Address) result.get("Address") == null);
		String value = (String) result.get("value");
		addLabel(value);
	}

	public TaintQueryResult(Map<String, Object> result, Run run, LogicalLocation ll) {
		this(
			SarifUtils.extractDisplayName(ll),
			ll.getDecoratedName(), 
			(Address) result.get("Address"),
			(Address) result.get("entry"),
			new ArrayList<String>(),
			(Address) result.get("Address") == null);
		String value = (String) result.get("value");
		addLabel(value);
	}

	public String getLabel() {
		return this.labels.get(0);
	}

	public String getQualifiedName() {
		return fqname;
	}

	public Address getInsnAddr() {
		return iaddr;
	}

	public void addLabel(String label) {
		labels.add(label);
	}

	public boolean hasLabel(String label) {
		return labels.contains(label);
	}

	public String matches(ClangToken token) {		
		String text = token.getText();
		String hvName = TaintState.varName(token, true);
		if (hvName == null) {
			return null;
		}

		Varnode vn = token.getVarnode();
		ClangFunction clangFunction = token.getClangFunction();
		Function function = clangFunction.getHighFunction().getFunction();
		boolean functionLevelToken = function.isThunk() || (vn == null);
		if (functionLevelToken) {
			if (faddr.equals(function.getEntryPoint())) {
				if (name.endsWith(hvName)) {
					return hvName;
				}
			}
		}
		else if (functionLevelResult) {
			if (faddr.equals(function.getEntryPoint())) {
				if (name.endsWith(hvName) || name.endsWith(text)) {
					return hvName;
				}
			}
		}
		else {
			Address vaddr = token.getMinAddress();
			if (vaddr == null) {
				HighVariable hv = token.getHighVariable();
				if (hv instanceof HighParam) {
					vaddr = hv.getRepresentative().getPCAddress();
				}
			}
			// if neither are function-level, the addresses must match
			// NB: parameter/local use matches on the representative
			if (iaddr.equals(vaddr)) {
				VarnodeAST ast = (VarnodeAST) vn;
				if (fqname.endsWith(":"+ast.getUniqueId())) {
					return hvName;
				}
				if (fqname.contains(":"+hvName)) {
					return hvName;
				}
			}
		}
		
		return null;
	}

	public boolean matchesFunction(String fname, Address entry_address) {
		return name.startsWith(fname) && iaddr.equals(entry_address);
	}

}
