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

import ghidra.app.decompiler.ClangFunction;
import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import sarif.SarifUtils;

public record TaintQueryResult(String name, String fqname, Address iaddr, Address faddr,
		List<String> labels, boolean functionLevelResult) {

	// NB: The constructors that follow depend on data generated at different phases in the processing.
	//   At first blush, it seems obvious that you could combine them by using the location data, accessed
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
		return labels.isEmpty() ? null : labels.get(0);
	}

	public String getQualifiedName() {
		return fqname;
	}

	public Address getInsnAddr() {
		return iaddr;
	}

	public void addLabel(String label) {
		if (label != null && !labels.contains(label)) {
			labels.add(label);
		}
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
		if (clangFunction == null) {
			return null;
		}
		HighFunction highFunction = clangFunction.getHighFunction();
		if (highFunction == null) {
			return null;
		}
		Function function = highFunction.getFunction();
		boolean functionLevelToken = function.isThunk() || (vn == null);
		if (functionLevelToken) {
			if (faddr != null && faddr.equals(function.getEntryPoint())) {
				if (endsWithSegment(name, hvName)) {
					return hvName;
				}
			}
		}
		else if (functionLevelResult) {
			if (faddr.equals(function.getEntryPoint())) {
				if (endsWithSegment(name, hvName) || endsWithSegment(name, text)) {
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
			if (iaddr != null && iaddr.equals(vaddr) && fqname != null) {
				VarnodeAST ast = (VarnodeAST) vn;
				if (fqname.endsWith(":" + ast.getUniqueId())) {
					return hvName;
				}
				if (containsSegment(fqname, hvName)) {
					return hvName;
				}
				if (containsSegment(fqname, ast.getAddress().toString())) {
					return hvName;
				}
			}
		}

		return null;
	}

	public boolean matchesFunction(String fname, Address entry_address) {
		if (!startsWithSegment(name, fname)) {
			return false;
		}
		if (iaddr != null) {
			return iaddr.equals(entry_address);
		}
		return faddr == null || faddr.equals(entry_address);
	}

	private static boolean isSeparator(char c) {
		return c == ':' || c == '@' || c == '.';
	}

	static boolean containsSegment(String qualified, String segment) {
		if (qualified == null || segment == null || segment.isEmpty()) {
			return false;
		}
		int from = 0;
		int idx;
		while ((idx = qualified.indexOf(segment, from)) >= 0) {
			boolean startOK = idx == 0 || isSeparator(qualified.charAt(idx - 1));
			int end = idx + segment.length();
			boolean endOK = end == qualified.length() || isSeparator(qualified.charAt(end));
			if (startOK && endOK) {
				return true;
			}
			from = idx + 1;
		}
		return false;
	}

	static boolean endsWithSegment(String qualified, String segment) {
		if (qualified == null || segment == null || segment.isEmpty()) {
			return false;
		}
		if (qualified.equals(segment)) {
			return true;
		}
		int idx = qualified.length() - segment.length();
		return idx > 0 && qualified.endsWith(segment) && isSeparator(qualified.charAt(idx - 1));
	}

	static boolean startsWithSegment(String qualified, String segment) {
		if (qualified == null || segment == null || segment.isEmpty()) {
			return false;
		}
		if (qualified.equals(segment)) {
			return true;
		}
		return qualified.startsWith(segment) &&
			isSeparator(qualified.charAt(segment.length()));
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TaintQueryResult other)) {
			return false;
		}
		// labels may or may not agree depending on the access time
		return Objects.equals(name, other.name) && Objects.equals(fqname, other.fqname) &&
			Objects.equals(iaddr, other.iaddr) && Objects.equals(faddr, other.faddr) &&
			functionLevelResult == other.functionLevelResult;
	}

	@Override
	public int hashCode() {
		// labels may or may not agree depending on the access time
		return Objects.hash(name, fqname, iaddr, faddr, functionLevelResult);
	}
}
