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
package ghidra.framework.data;

import java.io.IOException;

import db.DBHandle;

/**
 * Simple dummy version of DomainObjectAdapterDB
 */
public class DummyDomainObject extends DomainObjectAdapterDB {

	public DummyDomainObject(Object consumer) throws IOException {
		this("Dummy", consumer);
	}

	public DummyDomainObject(String name, Object consumer) throws IOException {
		super(new DBHandle(), name, 10, 1, consumer);
	}

	@Override
	public String getDescription() {
		return "Test object: " + getName();
	}

	@Override
	public boolean isChangeable() {
		return true;
	}
}
