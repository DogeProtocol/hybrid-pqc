#include "randombytes.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void *current_test = NULL;
static int syscall_called = 0;
static int glib_getrandom_called = 0;

#define RUN_TEST(name) \
	printf("%s ... ", #name); \
	padto(' ', sizeof(#name) + sizeof(" ... "), 32); \
	current_test = name; \
	name(); \
	printf("ok\n");
#define SKIP_TEST(name) \
	printf("%s ... ", #name); \
	padto(' ', sizeof(#name) + sizeof(" ... "), 32); \
	printf("skipped\n");

static void padto(const char c, const size_t curlen, const size_t len) {
	for (size_t i = curlen; i < len; i++) {
		putchar(c);
	}
}

static void test_functional(void) {
	uint8_t buf1[20] = { 0 };
	uint8_t buf2[sizeof(buf1)] = { 0 };
	const int ret1 = randombytes(buf1, sizeof(buf1));
	const int ret2 = randombytes(buf2, sizeof(buf2));
	if (ret1 != 0 || ret2 != 0) {
		printf("error: %s\n", strerror(errno));
	}
	assert(ret1 == 0);
	assert(ret2 == 0);
	assert(memcmp(buf1, buf2, sizeof(buf1)) != 0);
}

static void test_empty(void) {
	const uint8_t zero[20] = {0};
	uint8_t buf[sizeof(zero)] = {0};
	const int ret = randombytes(buf, 0);
	assert(ret == 0);
	assert(memcmp(buf, zero, sizeof(zero)) == 0);
}

static void test_getrandom_syscall_partial(void) {
	syscall_called = 0;
	uint8_t buf[100] = {0};
	const int ret = randombytes(buf, sizeof(buf));
	assert(ret == 0);
	assert(syscall_called >= 5);
	for (int i = 1; i < 5; i++) {
		assert(memcmp(&buf[0], &buf[20*i], 20) != 0);
	}
}

static void test_getrandom_syscall_interrupted(void) {
	syscall_called = 0;
	uint8_t zero[20] = {0};
	uint8_t buf[sizeof(zero)] = {0};
	const int ret = randombytes(buf, sizeof(buf));
	assert(ret == 0);
	assert(memcmp(buf, zero, 20) != 0);
}

static void test_getrandom_glib_partial(void) {
	glib_getrandom_called = 0;
	uint8_t buf[100] = {0};
	const int ret = randombytes(buf, sizeof(buf));
	assert(ret == 0);
	assert(glib_getrandom_called >= 5);
	for (int i = 1; i < 5; i++) {
		assert(memcmp(&buf[0], &buf[20*i], 20) != 0);
	}
}

static void test_getrandom_glib_interrupted(void) {
	glib_getrandom_called = 0;
	uint8_t zero[20] = {0};
	uint8_t buf[sizeof(zero)] = {0};
	const int ret = randombytes(buf, sizeof(buf));
	assert(ret == 0);
	assert(memcmp(buf, zero, 20) != 0);
}

static void test_issue_17(void) {
	uint8_t buf1[20] = { 0 };
	uint8_t buf2[sizeof(buf1)] = {0};
	const int ret1 = randombytes(buf1, sizeof(buf1));
	const int ret2 = randombytes(buf2, sizeof(buf2));
	assert(ret1 == 0);
	assert(ret2 == 0);
	assert(memcmp(buf1, buf2, sizeof(buf1)) != 0);
}

static void test_issue_22(void) {
	uint8_t buf1[20] = {0};
	uint8_t buf2[sizeof(buf1)] = {0};
	const int ret1 = randombytes(buf1, sizeof(buf1));
	const int ret2 = randombytes(buf2, sizeof(buf2));
	assert(ret1 == 0);
	assert(ret2 == 0);
	assert(memcmp(buf1, buf2, sizeof(buf1)) != 0);
}

static void test_issue_33(void) {
	for (size_t idx = 0; idx < 100000; idx++) {
		uint8_t buf[20] = {0};
		const int ret = randombytes(&buf, sizeof(buf));
		if (ret != 0) {
			printf("error: %s\n", strerror(errno));
		}
		assert(ret == 0);
	}
}

int main(void) {
	// Use `#if defined()` to enable/disable tests on a platform. If disabled,
	// please still call `SKIP_TEST` to make sure no tests are skipped silently.

	RUN_TEST(test_functional)
	RUN_TEST(test_empty)

#if defined(__linux__) && !defined(SYS_getrandom)
	RUN_TEST(test_issue_17)
	RUN_TEST(test_issue_22)
	RUN_TEST(test_issue_33)
#else
	SKIP_TEST(test_issue_17)
	SKIP_TEST(test_issue_22)
	SKIP_TEST(test_issue_33)
#endif /* defined(__linux__) && !defined(SYS_getrandom) */
	return 0;
}
