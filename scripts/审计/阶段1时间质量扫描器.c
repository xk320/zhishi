#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_BYTES (1024U * 1024U)
#define MAX_FIELDS 8
#define MAX_REASONS 20

static const char *reasons[MAX_REASONS];
static size_t reason_count = 0;

static void add_reason(const char *reason) {
    for (size_t index = 0; index < reason_count; ++index) {
        if (strcmp(reasons[index], reason) == 0) return;
    }
    if (reason_count < MAX_REASONS) reasons[reason_count++] = reason;
}

static bool is_uint(const char *value) {
    if (*value == '\0') return false;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return false;
    }
    return true;
}

static bool is_decimal(const char *value, bool positive) {
    bool dot = false;
    bool nonzero = false;
    bool digit = false;
    if (*value == '\0') return false;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; ++cursor) {
        if (*cursor == '.') {
            if (dot || !digit || cursor[1] == '\0') return false;
            dot = true;
        } else if (*cursor >= '0' && *cursor <= '9') {
            digit = true;
            if (*cursor != '0') nonzero = true;
        } else {
            return false;
        }
    }
    return digit && (!positive || nonzero);
}

static const char *normalized_uint(const char *value) {
    while (value[0] == '0' && value[1] != '\0') ++value;
    return value;
}

static int compare_uint(const char *left, const char *right) {
    left = normalized_uint(left);
    right = normalized_uint(right);
    size_t left_length = strlen(left);
    size_t right_length = strlen(right);
    if (left_length != right_length) return left_length < right_length ? -1 : 1;
    int compared = strcmp(left, right);
    return compared < 0 ? -1 : compared > 0 ? 1 : 0;
}

static bool normalize_event_time(const char *value, char output[14]) {
    size_t length = strlen(value);
    if (!is_uint(value) || (length != 13 && length != 16)) return false;
    memcpy(output, value, 13);
    output[13] = '\0';
    return true;
}

static bool parse_u64(const char *value, uint64_t *output) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') return false;
    *output = (uint64_t)parsed;
    return true;
}

int main(int argc, char **argv) {
    if (argc != 8) return 64;
    const char *dataset = argv[1];
    int expected_columns = atoi(argv[2]);
    int time_index = atoi(argv[3]) - 1;
    bool header_expected = strcmp(argv[4], "1") == 0;
    const char *header = argv[5];
    uint64_t date_start = 0, date_end = 0;
    if ((strcmp(dataset, "trades") != 0 && strcmp(dataset, "aggTrades") != 0) ||
        expected_columns <= 0 || expected_columns > MAX_FIELDS || time_index < 0 ||
        time_index >= expected_columns || !parse_u64(argv[6], &date_start) ||
        !parse_u64(argv[7], &date_end) || date_start >= date_end) return 64;

    char *line = malloc(MAX_LINE_BYTES + 2U);
    if (line == NULL) return 70;
    char *first_key = NULL, *last_key = NULL;
    char first_time[14] = "", last_time[14] = "";
    uint64_t row_count = 0, byte_count = 0, physical_line = 0;

    while (fgets(line, (int)MAX_LINE_BYTES + 2, stdin) != NULL) {
        ++physical_line;
        size_t length = strlen(line);
        byte_count += length;
        bool complete = length > 0 && line[length - 1] == '\n';
        if (!complete && !feof(stdin)) {
            add_reason("LINE_TOO_LONG");
            int character;
            while ((character = fgetc(stdin)) != EOF) {
                ++byte_count;
                if (character == '\n') break;
            }
            ++row_count;
            continue;
        }
        if (complete) line[--length] = '\0';
        if (length > 0 && line[length - 1] == '\r') line[--length] = '\0';
        if (strchr(line, '"') != NULL) add_reason("QUOTED_FIELD_REJECTED");
        if (header_expected && physical_line == 1) {
            if (strcmp(line, header) != 0) add_reason("HEADER_INVALID");
            continue;
        }
        if (length == 0) {
            add_reason("EMPTY_LINE");
            continue;
        }
        ++row_count;

        char *fields[MAX_FIELDS] = {0};
        int field_count = 1;
        fields[0] = line;
        for (char *cursor = line; *cursor; ++cursor) {
            if (*cursor == ',') {
                *cursor = '\0';
                if (field_count < MAX_FIELDS) fields[field_count] = cursor + 1;
                ++field_count;
            }
        }
        if (field_count != expected_columns || field_count > MAX_FIELDS) {
            add_reason("COLUMN_COUNT_INVALID");
            continue;
        }
        const char *key = fields[0];
        char event_time[14] = "";
        bool key_valid = is_uint(key);
        bool time_valid = normalize_event_time(fields[time_index], event_time);
        if (!key_valid) add_reason("BUSINESS_KEY_INVALID");
        if (!time_valid) add_reason("EVENT_TIME_INVALID");
        if (!is_decimal(fields[1], true) || !is_decimal(fields[2], true)) add_reason("DECIMAL_INVALID");
        if (strcmp(dataset, "trades") == 0) {
            if (!is_decimal(fields[3], false)) add_reason("DECIMAL_INVALID");
            if (strcmp(fields[5], "true") != 0 && strcmp(fields[5], "false") != 0) add_reason("BOOLEAN_INVALID");
        } else {
            if (!is_uint(fields[3]) || !is_uint(fields[4]) || compare_uint(fields[3], fields[4]) > 0) add_reason("AGG_TRADE_RANGE_INVALID");
            if (strcmp(fields[6], "true") != 0 && strcmp(fields[6], "false") != 0) add_reason("BOOLEAN_INVALID");
        }
        if (key_valid && last_key != NULL && compare_uint(key, last_key) <= 0) add_reason("DUPLICATE_OR_REVERSED_KEY");
        if (time_valid && last_time[0] != '\0' && compare_uint(event_time, last_time) < 0) add_reason("EVENT_TIME_REVERSED");
        if (time_valid) {
            uint64_t milliseconds = 0;
            if (!parse_u64(event_time, &milliseconds) || milliseconds < date_start || milliseconds >= date_end) add_reason("EVENT_DATE_MISMATCH");
        }
        if (key_valid) {
            if (first_key == NULL) first_key = strdup(key);
            free(last_key);
            last_key = strdup(key);
            if (first_key == NULL || last_key == NULL) {
                free(line); free(first_key); free(last_key); return 70;
            }
        }
        if (time_valid) {
            if (first_time[0] == '\0') memcpy(first_time, event_time, sizeof(first_time));
            memcpy(last_time, event_time, sizeof(last_time));
        }
    }
    if (ferror(stdin)) add_reason("INPUT_READ_FAILED");
    if (row_count == 0) add_reason("EMPTY_MEMBER");
    printf("%s\t%llu\t%llu\t%s\t%s\t%s\t%s\t",
           reason_count == 0 ? "已证明" : "拒绝",
           (unsigned long long)row_count, (unsigned long long)byte_count,
           first_key == NULL ? "" : first_key, last_key == NULL ? "" : last_key,
           first_time, last_time);
    for (size_t index = 0; index < reason_count; ++index) {
        if (index > 0) putchar(',');
        fputs(reasons[index], stdout);
    }
    putchar('\n');
    free(line); free(first_key); free(last_key);
    return 0;
}
