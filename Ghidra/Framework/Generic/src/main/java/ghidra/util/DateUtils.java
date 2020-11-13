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
package ghidra.util;

import static java.util.Calendar.*;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.TemporalAccessor;
import java.util.*;
import java.util.function.Predicate;

import ghidra.util.exception.AssertException;

public class DateUtils {

	/** Example: Oct 31, 2019 03:24 PM */
	private static final String DATE_TIME_FORMAT_STRING = "MMM dd, yyyy hh:mm a";
	private static final String DATE_FORMAT_STRING = "MM/dd/yyyy";
	private static final String TIME_FORMAT_STRING = "h:mm";

	private static final DateTimeFormatter DATE_TIME_FORMATTER =
		DateTimeFormatter.ofPattern(DATE_TIME_FORMAT_STRING);
	private static final DateTimeFormatter DATE_FORMATTER =
		DateTimeFormatter.ofPattern(DATE_FORMAT_STRING);
	private static final DateTimeFormatter TIME_FORMATTER =
		DateTimeFormatter.ofPattern(TIME_FORMAT_STRING);

	public static final long MS_PER_SEC = 1000;
	public static final long MS_PER_MIN = MS_PER_SEC * 60;
	public static final long MS_PER_HOUR = MS_PER_MIN * 60;
	public static final long MS_PER_DAY = MS_PER_HOUR * 24;

	public static List<Date> getHolidays(int year) {
		List<Date> holidays = new ArrayList<>();

		holidays.add(getNewYearsHoliday(year));
		holidays.add(getMLKDay(year));
		holidays.add(getPresidentsDay(year));
		holidays.add(getMemorialDay(year));
		holidays.add(getIndependanceHoliday(year));
		holidays.add(getLaborDay(year));
		holidays.add(getColumbusDay(year));
		holidays.add(getVeterensDay(year));
		holidays.add(getThanksgivingDay(year));
		holidays.add(getChristmasHoliday(year));

		return holidays;
	}

	public static boolean isHoliday(Date date) {
		date = normalizeDate(date);
		Calendar cal = new GregorianCalendar();
		cal.setTime(date);
		int month = cal.get(MONTH);
		int year = cal.get(YEAR);
		switch (month) {
			case JANUARY:
				return date.equals(getNewYearsHoliday(year)) || date.equals(getMLKDay(year));
			case FEBRUARY:
				return date.equals(getPresidentsDay(year));
			case MAY:
				return date.equals(getMemorialDay(year));
			case JULY:
				return date.equals(getIndependanceHoliday(year));
			case SEPTEMBER:
				return date.equals(getLaborDay(year));
			case OCTOBER:
				return date.equals(getColumbusDay(year));
			case NOVEMBER:
				return date.equals(getVeterensDay(year)) || date.equals(getThanksgivingDay(year));
			case DECEMBER:
				return date.equals(getChristmasHoliday(year)) ||
					date.equals(getNewYearsHoliday(year + 1));
			default:
				return false;
		}
	}

	public static Date getNormalizedToday() {
		return normalizeDate(new Date());
	}

	// Dec 25
	private static Date getChristmasHoliday(int year) {
		Calendar cal = new GregorianCalendar(year, DECEMBER, 25);
		adjustForWeekend(cal);
		return cal.getTime();
	}

	// 4th Thursday in November
	private static Date getThanksgivingDay(int year) {
		Calendar cal = getFirstDayOfWeekInMonth(year, NOVEMBER, THURSDAY);
		cal.add(DAY_OF_MONTH, 21);
		return cal.getTime();
	}

	// Nov 11
	private static Date getVeterensDay(int year) {
		Calendar cal = new GregorianCalendar(year, NOVEMBER, 11);
		adjustForWeekend(cal);
		return cal.getTime();
	}

	// 2nd Monday in October
	private static Date getColumbusDay(int year) {
		Calendar cal = getFirstDayOfWeekInMonth(year, OCTOBER, MONDAY);
		cal.add(DAY_OF_MONTH, 7);
		return cal.getTime();
	}

	// First Monday in September
	private static Date getLaborDay(int year) {
		Calendar cal = getFirstDayOfWeekInMonth(year, SEPTEMBER, MONDAY);
		return cal.getTime();
	}

	// July 4
	private static Date getIndependanceHoliday(int year) {
		Calendar cal = new GregorianCalendar(year, JULY, 4);
		adjustForWeekend(cal);
		return cal.getTime();
	}

	// Last Monday in May
	private static Date getMemorialDay(int year) {
		Calendar cal = getLastDayOfWeekInMonth(year, MAY, MONDAY);
		return cal.getTime();
	}

	// 3rd Monday in February
	private static Date getPresidentsDay(int year) {
		Calendar cal = getFirstDayOfWeekInMonth(year, FEBRUARY, MONDAY);
		cal.add(DAY_OF_MONTH, 14);
		return cal.getTime();
	}

	// 3rd Monday in January
	private static Date getMLKDay(int year) {
		Calendar cal = getFirstDayOfWeekInMonth(year, JANUARY, MONDAY);
		cal.add(DAY_OF_MONTH, 14);
		return cal.getTime();
	}

	// Jan 1
	private static Date getNewYearsHoliday(int year) {
		Calendar cal = new GregorianCalendar(year, JANUARY, 1);
		adjustForWeekend(cal);
		return cal.getTime();
	}

	private static Calendar getFirstDayOfWeekInMonth(int year, int month, int dayOfWeek) {
		Calendar cal = new GregorianCalendar(year, month, 1);
		int day = cal.get(DAY_OF_WEEK);
		while (day != dayOfWeek) {
			cal.add(DAY_OF_WEEK, 1);
			day = cal.get(DAY_OF_WEEK);
		}
		return cal;
	}

	private static void adjustForWeekend(Calendar cal) {
		int dayOfWeek = cal.get(DAY_OF_WEEK);
		if (dayOfWeek == SATURDAY) {
			cal.add(DAY_OF_MONTH, -1);
		}
		if (dayOfWeek == SUNDAY) {
			cal.add(DAY_OF_MONTH, 1);
		}
	}

	private static Calendar getLastDayOfWeekInMonth(int year, int month, int dayOfWeek) {
		Calendar cal = new GregorianCalendar(year, month, 1);
		cal.add(MONTH, 1);
		cal.add(DAY_OF_MONTH, -1);
		int day = cal.get(DAY_OF_WEEK);
		while (day != dayOfWeek) {
			cal.add(DAY_OF_WEEK, -1);
			day = cal.get(DAY_OF_WEEK);
		}
		return cal;
	}

	public static boolean isHoliday(Calendar cal) {
		return isHoliday(cal.getTime());
	}

	public static boolean isWeekend(Calendar cal) {
		int dayOfWeek = cal.get(DAY_OF_WEEK);
		return dayOfWeek == SATURDAY || dayOfWeek == SUNDAY;
	}

	public static Date normalizeDate(Date date) {
		try {
			DateTimeFormatter dtf = DATE_FORMATTER;
			TemporalAccessor ta = dtf.parse(dtf.format(toLocalDate(date)));
			LocalDate localDateTime = LocalDate.from(ta);
			return toDate(localDateTime);
		}
		catch (DateTimeParseException e) {
			throw new AssertException("Unexpected exception parsing date from a known format", e);
		}
	}

	/**
	 * Formats the given date into a string.   This is in contrast to 
	 * {@link #formatDateTimestamp(Date)}, which will also return the time portion of the date.
	 * 
	 * @param date the date to format
	 * @return the date string
	 */
	public static String formatDate(Date date) {
		return DATE_FORMATTER.format(toLocalDate(date));
	}

	/**
	 * Formats the given date into a string that contains the date and time.  This is in 
	 * contrast to {@link #formatDate(Date)}, which only returns a date string.
	 * 
	 * @param date the date to format
	 * @return the date and time string
	 */
	public static String formatDateTimestamp(Date date) {
		return DATE_TIME_FORMATTER.format(toLocalDate(date));
	}

	/**
	 * Returns the current local time zone time-of-day as simple time string. 
	 * See {@value #TIME_FORMAT_STRING}.
	 *
	 * @return current time-of-day a a string
	 */
	public static String formatCurrentTime() {
		return TIME_FORMATTER.format(toLocalDate(new Date()));
	}

	private static LocalDateTime toLocalDate(Date d) {
		//@formatter:off
		return Instant.ofEpochMilli(d.getTime())
			       .atZone(ZoneId.systemDefault())
	               .toLocalDateTime()
	               ;
		//@formatter:on
	}

	private static Date toDate(LocalDate ld) {
		//@formatter:off
		  return Date.from(ld.atStartOfDay()
			  		 .atZone(ZoneId.systemDefault())
			  		 .toInstant())
				  	 ;
		//@formatter:on
	}

	/**
	 * Returns a date for the given numeric values
	 * 
	 * @param year the year 
	 * @param month the month; 0-based
	 * @param day the day of month; 1-based
	 * @return the date
	 */
	public static Date getDate(int year, int month, int day) {
		Calendar cal = new GregorianCalendar(year, month, day);
		return cal.getTime();
	}

	/**
	 * Returns all days between the two dates.  Returns 0 if the same date is passed for both
	 * parameters.  The order of the dates does not matter.
	 * 
	 * @param date1 the first date
	 * @param date2 the second date
	 * @return the number of days
	 */
	public static int getDaysBetween(Date date1, Date date2) {
		return doGetDaysBetween(date1, date2, DateUtils::anyDay);
	}

	/**
	 * Returns the <b>business days</b> between the two dates.  Returns 0 if the same date is 
	 * passed for both parameters.  The order of the dates does not matter.
	 * 
	 * @param date1 the first date
	 * @param date2 the second date
	 * @return the number of days
	 */
	public static int getBusinessDaysBetween(Date date1, Date date2) {
		return doGetDaysBetween(date1, date2, DateUtils::isBusinessDay);
	}

	private static boolean anyDay(Calendar c) {
		return true;
	}

	private static boolean isBusinessDay(Calendar c) {
		return !(isWeekend(c) || isHoliday(c));
	}

	private static int doGetDaysBetween(Date date1, Date date2, Predicate<Calendar> dayFilter) {

		Date d1 = date1;
		Date d2 = date2;
		if (date1.compareTo(date2) > 0) {
			d1 = date2;
			d2 = date1;
		}

		d1 = normalizeDate(d1);
		d2 = normalizeDate(d2);

		Calendar cal = new GregorianCalendar();
		cal.setTime(d1);
		int days = 0;
		while (cal.getTime().compareTo(d2) < 0) {
			cal.add(Calendar.DAY_OF_MONTH, 1);
			if (dayFilter.test(cal)) {
				days++;
			}
		}
		return days;
	}

	/**
	 * Formats a millisecond duration as a English string expressing the number of
	 * hours, minutes and seconds in the duration
	 *
	 * @param millis Count of milliseconds of an elapsed duration.
	 * @return String such as "5 hours, 3 mins, 22 secs".
	 */
	public static String formatDuration(long millis) {
		long days = 0;
		int hours = 0;
		int minutes = 0;
		int seconds = 0;
		if (millis >= MS_PER_DAY) {
			days = millis / MS_PER_DAY;
			millis = millis % MS_PER_DAY;
		}
		if (millis >= MS_PER_HOUR) {
			hours = (int) (millis / MS_PER_HOUR);// this cast is safe
			millis = millis % MS_PER_HOUR;
		}
		if (millis >= MS_PER_MIN) {
			minutes = (int) (millis / MS_PER_MIN);
			millis = millis % MS_PER_MIN;
		}
		if (millis >= MS_PER_SEC) {
			seconds = (int) (millis / MS_PER_SEC);
			millis = millis % MS_PER_SEC;
		}
		StringBuilder sb = new StringBuilder();
		if (days > 0) {
			sb.append(Long.toString(days)).append(" days, ");
		}
		if (sb.length() > 0 || hours > 0) {
			sb.append(Integer.toString(hours)).append(" hours, ");
		}
		if (sb.length() > 0 || minutes > 0) {
			sb.append(Integer.toString(minutes)).append(" mins, ");
		}
		sb.append(Integer.toString(seconds)).append(" secs");

		return sb.toString();
	}
}
