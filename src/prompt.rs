use time::OffsetDateTime;

fn weekday_name(weekday: time::Weekday) -> &'static str {
    match weekday {
        time::Weekday::Monday => "Monday",
        time::Weekday::Tuesday => "Tuesday",
        time::Weekday::Wednesday => "Wednesday",
        time::Weekday::Thursday => "Thursday",
        time::Weekday::Friday => "Friday",
        time::Weekday::Saturday => "Saturday",
        time::Weekday::Sunday => "Sunday",
    }
}

fn month_name(month: time::Month) -> &'static str {
    match month {
        time::Month::January => "January",
        time::Month::February => "February",
        time::Month::March => "March",
        time::Month::April => "April",
        time::Month::May => "May",
        time::Month::June => "June",
        time::Month::July => "July",
        time::Month::August => "August",
        time::Month::September => "September",
        time::Month::October => "October",
        time::Month::November => "November",
        time::Month::December => "December",
    }
}

pub fn current_datetime_prompt_line_at(now: OffsetDateTime) -> String {
    format!(
        "Current date and time: {}, {} {}, {} at {:02}:{:02} UTC",
        weekday_name(now.weekday()),
        month_name(now.month()),
        now.day(),
        now.year(),
        now.hour(),
        now.minute()
    )
}

pub fn current_datetime_prompt_line() -> String {
    current_datetime_prompt_line_at(OffsetDateTime::now_utc())
}

#[cfg(test)]
mod tests {
    use super::current_datetime_prompt_line_at;
    use time::macros::datetime;

    #[test]
    fn current_datetime_prompt_line_includes_weekday_date_time_and_timezone() {
        assert_eq!(
            current_datetime_prompt_line_at(datetime!(2026-05-09 17:12 UTC)),
            "Current date and time: Saturday, May 9, 2026 at 17:12 UTC"
        );
    }
}
