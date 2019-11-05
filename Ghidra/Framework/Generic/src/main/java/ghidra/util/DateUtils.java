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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import ghidra.util.exception.AssertException;

public class DateUtils {

	/** Example: Oct 31, 2019 03:24 PM */
	private static final String DATE_TIME_FORMAT_STRING = "MMM dd, yyyy hh:mm a";
	private static final String DATE_FORMAT_STRING = "MM/dd/yyyy";
	private static final String TIME_FORMAT_STRING = "h:mm";

	private static final ThreadLocal<SimpleDateFormat> DATE_TIME_FORMAT =
		ThreadLocal.withInitial(() -> new SimpleDateFormat(DATE_TIME_FORMAT_STRING));

	private static final ThreadLocal<SimpleDateFormat> DATE_FORMAT =
		ThreadLocal.withInitial(() -> new SimpleDateFormat(DATE_FORMAT_STRING));

	private static final ThreadLocal<SimpleDateFormat> TIME_FORMAT =
		ThreadLocal.withInitial(() -> new SimpleDateFormat(TIME_FORMAT_STRING));

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

	public static Date normalizeDate(Date date) {
		try {
			SimpleDateFormat sdf = DATE_FORMAT.get();
			return sdf.parse(sdf.format(date));
		}
		catch (ParseException e) {
			throw new AssertException("Can't happend parsing date from formated date");
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

	/**
	 * Formats the given date into a string.  This is in contrast to 
	 * {@link #formatDateTimestamp(Date)}, which will also return the time portion of the date.
	 * 
	 * @param date the date to format
	 * @return the date string
	 */
	public static String formatDate(Date date) {
		return DATE_FORMAT.get().format(date);
	}

	/**
	 * Formats the given date into a string that contains the date and time.  This is in 
	 * contrast to {@link #formatDate(Date)}, which only returns a date string.
	 * 
	 * @param date the date to format
	 * @return the date and time string
	 */
	public static String formatDateTimestamp(Date date) {
		return DATE_TIME_FORMAT.get().format(date);
	}

	/**
	 * Returns the current local time zone time-of-day as simple time string. 
	 * See {@value #TIME_FORMAT_STRING}.
	 *
	 * @return current time-of-day a a string
	 */
	public static String formatCurrentTime() {
		return TIME_FORMAT.get().format(new Date());
	}

	public static Date getDate(int year, int month, int day) {
		Calendar cal = new GregorianCalendar(year, month, day);
		return cal.getTime();
	}

	public static int getDaysBetween(Date date1, Date date2) {
		date1 = normalizeDate(date1);
		date2 = normalizeDate(date2);

		Calendar cal = new GregorianCalendar();
		cal.setTime(date1);
		int days = 0;
		while (cal.getTime().compareTo(date2) < 0) {
			cal.add(Calendar.DAY_OF_MONTH, 1);
			if (!isWeekend(cal) && !isHoliday(cal)) {
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
