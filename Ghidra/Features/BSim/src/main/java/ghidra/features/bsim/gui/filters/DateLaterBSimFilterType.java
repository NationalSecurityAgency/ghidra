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
package ghidra.features.bsim.gui.filters;

import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

import ghidra.features.bsim.query.client.*;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.elastic.*;
import ghidra.features.bsim.query.protocol.FilterAtom;

/**
 * A BsimFilterType for filtering on functions in programs created after the filter date.
 */
public class DateLaterBSimFilterType extends DateBSimFilterType {
	public static final String XML_VALUE = "datelater";

	public DateLaterBSimFilterType(String sub) {
		super(sub + " is later than", XML_VALUE, "1974-09-21 or 09/21/1974");
	}

	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		LocalDate localDate = formatDate(atom.value);
		if (localDate == null) {
			return;
		}
		//localDate is a calendar date, i.e., does not specify hours/minutes/seconds
		//the database records timestamps for executables, so we need to create a timestamp 
		//from localDate.  The timestamp we create corresponds to midnight on the day after 
		//localDate *in the system default time zone of the client*.  If an executable's 
		//ingest timestamp is greater than or equal to this timestamp, it passes the filter
		localDate = localDate.plusDays(1);
		Date date =
			Date.from(localDate.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
		effect.setExeTable();
		String dateString =
			new SimpleDateFormat(AbstractSQLFunctionDatabase.JAVA_TIME_FORMAT).format(date);
		StringBuilder buf = new StringBuilder();
		buf.append("exetable.ingest_date >= to_timestamp('")
			.append(dateString)
			.append("','" + AbstractSQLFunctionDatabase.SQL_TIME_FORMAT + "')");
		effect.addWhere(this, buf.toString());
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		LocalDate localDate = formatDate(atom.value);
		Date date =
			Date.from(localDate.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
		if (date == null) {
			return;
		}

		effect.addDocValue("ZonedDateTime date = doc['ingest_date'].value; ");
		String argName = effect.assignArgument();
		effect.addScriptElement(this, "ZonedDateTime.ofInstant(Instant.ofEpochMilli(params." +
			argName + "), ZoneId.of('Z')).compareTo(date) <= 0");
		effect.addDateParam(argName, date);
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		LocalDate localDate = formatDate(value);
		Date date =
			Date.from(localDate.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
		if (date == null) {
			return true; // Don't filter anything if we can't get a date
		}
		return rec.getDate().after(date);
	}
}
