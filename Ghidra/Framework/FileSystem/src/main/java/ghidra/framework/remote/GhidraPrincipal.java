/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.remote;

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;

/**
 * <code>GhidraPrincipal</code> specifies a Ghidra user as a Principal
 * for use with server login/authentication.
 */
public class GhidraPrincipal implements Principal, java.io.Serializable {
	
	public final static long serialVersionUID = 1L;

	private String username;
	
	/**
	 * Constructor.
	 * @param username user id/name
	 */
	public GhidraPrincipal(String username) {
		this.username = username;
	}
	
	/*
	 * @see java.security.Principal#getName()
	 */
	public String getName() {
		return username;
	}
	
	/**
	 * Returns the GhidraPrincipal object contained within a Subject, or null if
	 * not found.
	 * 
	 * @param subj user subject
	 * @return GhidraPrincipal or null
	 */
	public static GhidraPrincipal getGhidraPrincipal(Subject subj) {
		if (subj != null) {
			Set<GhidraPrincipal> set = subj.getPrincipals(GhidraPrincipal.class);
			if (!set.isEmpty()) {
				return set.iterator().next();
			}
		}
		return null;
	}
	
}
