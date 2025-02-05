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
			SarifUtils.extractDisplayName(fqnFromLoc(run, ll)),
			fqnFromLoc(run, ll).getFullyQualifiedName(), 
			(Address) result.get("Address"),
			(Address) result.get("entry"),
			new ArrayList<String>(),
			(Address) result.get("Address") == null);
		String value = (String) result.get("value");
		addLabel(value);
	}

	private static LogicalLocation fqnFromLoc(Run run, LogicalLocation ll) {
		String fqn = ll.getFullyQualifiedName();
		if (fqn == null) {
			ll = SarifUtils.getLogicalLocation(run, ll.getIndex());
		}
		return ll;
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
		Address vaddr = token.getMinAddress();
		HighVariable hv = token.getHighVariable();
		ClangToken hvToken = token;
		if (hv == null && token instanceof ClangFieldToken ftoken) {
			ClangVariableToken vtoken = TaintState.getParentToken(ftoken);
			if (vtoken != null) {
				hv = vtoken.getHighVariable();
				hvToken = vtoken;
			}
		}
		if (hv == null) {
			return null;
		}
		HighFunction hf = hv.getHighFunction();
		String hvName = TaintState.hvarName(hvToken);

		// Weed-out check
		if (!fqname.contains(hvName) && !fqname.contains(text)) {
			return null;
		}
		Function function = hf.getFunction();
		Varnode vn = token.getVarnode();
		boolean functionLevelToken = function.isThunk() || (vn == null);
		if (functionLevelToken || functionLevelResult) {
			if (!faddr.equals(function.getEntryPoint())) {
				return null;
			}
		}
		else {
			// if neither are function-level, the addresses must match
			if (!iaddr.equals(vaddr)) {
				return null;
			}
		}
		if (hvName.startsWith(":")) { // fqname is FUN@FUN:name:vname
			if (fqname.endsWith(hvName) || fqname.endsWith(text)) {
				return hvName;
			}
		}
		else { // fqname is FUN@FUN:vname:id
			if (fqname.contains(":" + hvName + ":") || fqname.contains(":" + text + ":")) {
				return hvName;
			}
		}
		return null;
	}

	public boolean matchesFunction(String fname, Address entry_address) {
		return name.startsWith(fname) && iaddr.equals(entry_address);
	}

}
