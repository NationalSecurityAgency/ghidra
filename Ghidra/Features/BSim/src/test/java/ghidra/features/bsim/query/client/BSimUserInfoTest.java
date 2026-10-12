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
package ghidra.features.bsim.query.client;

import static org.junit.Assert.*;

import java.net.URL;

import org.apache.commons.dbcp2.BasicDataSource;
import org.junit.Test;

import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/** Exercises public connection information before it reaches the actual data source. */
public class BSimUserInfoTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void testPostgresRejectsEmptyPassword() {
		rejectExplicit(DBType.postgres, "alice:");
	}

	@Test
	public void testElasticRejectsEmptyPassword() {
		rejectExplicit(DBType.elastic, "alice:");
	}

	@Test
	public void testPostgresUrlRejectsEmptyPassword() throws Exception {
		rejectUrl(DBType.postgres, "alice:");
	}

	@Test
	public void testElasticUrlRejectsEmptyPassword() throws Exception {
		rejectUrl(DBType.elastic, "alice:");
	}

	@Test
	public void testTrimmedExplicitRejectsEmptyPassword() {
		for (DBType type : new DBType[] { DBType.postgres, DBType.elastic }) {
			rejectExplicit(type, "  alice:  ");
		}
	}

	@Test
	public void testDecodedUrlRejectsEmptyPassword() throws Exception {
		for (DBType type : new DBType[] { DBType.postgres, DBType.elastic }) {
			rejectUrl(type, "alice:%20");
		}
	}

	@Test
	public void testUsernameOnlyControl() throws Exception {
		for (DBType type : new DBType[] { DBType.postgres, DBType.elastic }) {
			checkLogin(new BSimServerInfo(type, "alice", "localhost", -1, "db"), "alice", null);
			checkLogin(new BSimServerInfo(url(type, "alice")), "alice", null);
		}
	}

	@Test
	public void testPasswordContainsColonsControl() throws Exception {
		for (DBType type : new DBType[] { DBType.postgres, DBType.elastic }) {
			checkLogin(new BSimServerInfo(type, "alice:p:a:", "localhost", -1, "db"), "alice", "p:a:");
			checkLogin(new BSimServerInfo(url(type, "alice:p%3Aa%3A")), "alice", "p:a:");
		}
	}

	@Test
	public void testBlankDefaultLoginControl() {
		for (DBType type : new DBType[] { DBType.postgres, DBType.elastic }) {
			for (String input : new String[] { null, "", "  " }) {
				BSimServerInfo info = new BSimServerInfo(type, input, "localhost", -1, "db");
				assertTrue(info.hasDefaultLogin());
				assertNull(info.getUserInfo());
				assertFalse(info.hasPassword());
			}
		}
	}

	@Test
	public void testMissingUsernameControl() throws Exception {
		for (DBType type : new DBType[] { DBType.postgres, DBType.elastic }) {
			rejectExplicit(type, ":password");
			rejectUrl(type, ":password");
		}
	}

	@Test
	public void testTrimmedValidLoginControl() throws Exception {
		for (DBType type : new DBType[] { DBType.postgres, DBType.elastic }) {
			checkLogin(new BSimServerInfo(type, "  alice:password  ", "localhost", -1, "db"), "alice", "password");
			checkLogin(new BSimServerInfo(url(type, "alice:password")), "alice", "password");
		}
	}

	@Test
	public void testFileIgnoresUserInfoControl() {
		BSimServerInfo info = new BSimServerInfo(DBType.file, "alice:", null, -1, "/tmp/bsim-test");
		assertNull(info.getUserInfo());
		assertNull(info.getUserName());
		assertFalse(info.hasPassword());
	}

	private void rejectExplicit(DBType type, String input) {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> new BSimServerInfo(type, input, "localhost", -1, "db"));
		assertEquals("Invalid userinfo specified", e.getMessage());
	}

	private void rejectUrl(DBType type, String input) throws Exception {
		URL actual = url(type, input);
		assertEquals(input, actual.getUserInfo());
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
			() -> new BSimServerInfo(actual));
		assertEquals("Invalid userinfo specified", e.getMessage());
	}

	private URL url(DBType type, String input) throws Exception {
		if (type == DBType.postgres) {
			return new URL(null, "postgresql://" + input + "@localhost/db",
				new ghidra.features.bsim.query.postgresql.Handler());
		}
		return new URL(null, "elastic://" + input + "@localhost/db",
			new ghidra.features.bsim.query.elastic.Handler());
	}

	private void checkLogin(BSimServerInfo info, String user, String password) throws Exception {
		assertEquals(user, info.getUserName());
		assertFalse(info.hasDefaultLogin());
		assertEquals(password != null, info.hasPassword());
		try (BasicDataSource actual = new BasicDataSource()) {
			info.setUserInfo(actual);
			assertEquals(user, actual.getUsername());
			assertEquals(password, actual.getPassword());
		}
	}
}
