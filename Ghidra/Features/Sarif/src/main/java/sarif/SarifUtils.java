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
package sarif;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.util.encoders.Base64;

import com.contrastsecurity.sarif.Artifact;
import com.contrastsecurity.sarif.ArtifactContent;
import com.contrastsecurity.sarif.ReportingDescriptor;
import com.contrastsecurity.sarif.ReportingDescriptorReference;
import com.contrastsecurity.sarif.Run;
import com.contrastsecurity.sarif.ToolComponent;

public class SarifUtils {
	
	public static ByteArrayInputStream getArtifactContent(Artifact artifact) {
		ArtifactContent content = artifact.getContents();
		String b64 = content.getBinary();
		byte[] decoded = Base64.decode(b64);
		return new ByteArrayInputStream(decoded);
	}

	public static ReportingDescriptor getTaxaValue(ReportingDescriptorReference taxa, ToolComponent taxonomy) {
		List<ReportingDescriptor> view = new ArrayList<>(taxonomy.getTaxa());
		return view.get(taxa.getIndex().intValue());
	}

	public static ToolComponent getTaxonomy(ReportingDescriptorReference taxa, Set<ToolComponent> taxonomies) {
		Object idx = taxa.getToolComponent().getIndex();
		if (idx == null) {
			List<ToolComponent> view = new ArrayList<>(taxonomies);
			idx= taxa.getIndex();
			return view.get(idx instanceof Long ? ((Long)idx).intValue() : (Integer) idx);
		}
		for (ToolComponent taxonomy : taxonomies) {
			if (taxonomy.getName().equals(taxa.getToolComponent().getName())) {
				return taxonomy;
			}
		}
		return null;
	}

	public static List<String> getTaxonomyNames(Run sarifRun) {
		List<String> names = new ArrayList<>();
		Set<ToolComponent> taxonomies = sarifRun.getTaxonomies();
		if (taxonomies != null) {
			for (ToolComponent taxonomy : sarifRun.getTaxonomies()) {
				names.add(taxonomy.getName());
			}
		}
		return names;
	}

}
