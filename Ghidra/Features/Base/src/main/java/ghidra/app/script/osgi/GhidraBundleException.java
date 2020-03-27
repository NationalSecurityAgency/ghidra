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

package ghidra.app.script.osgi;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleException;

public class GhidraBundleException extends OSGiException {
	private Bundle bundle;
	private String bundle_loc;

	public GhidraBundleException(Bundle bundle, String msg, Throwable cause) {
		super(msg, cause);
		this.bundle = bundle;
	}

	public GhidraBundleException(Bundle bundle, String msg) {
		super(msg);
		this.bundle = bundle;
	}

	public GhidraBundleException(String bundle_loc, String msg, BundleException cause) {
		super(msg, cause);
		this.bundle_loc = bundle_loc;
	}

	public Bundle getBundle() {
		return bundle;
	}

	public String getBundleLocation() {
		return bundle_loc;
	}

}
