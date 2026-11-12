// SPDX-License-Identifier: AGPL-3.0-only

// Compiled (never linked or run) inside a platform/external/boringssl checkout
// against its own src/ssl/internal.h, once per Android architecture with the
// NDK's clang, so the layout is the one Conscrypt's libssl.so has on a device
// of that release. boringssl.sh reads the constants from the assembly output.
// The ssl_log_secret uprobe gets the SSL * and the secret as arguments, so it
// only needs the negotiated version, which checks the layout, and the path to
// the client_random: ssl_st.s3 points at the SSL3_STATE that holds it.
// Up to android15-release the version is ssl_st.version, from
// android16-release on it moved to SSL3_STATE.version.
#include <stddef.h>

#include <type_traits>

#include "ssl/internal.h"

// the uprobe reads the arguments from registers: SSL *, label, and the Span as
// two more registers (data, size), which holds only while the signature and a
// two word, trivially copyable Span stay; decerter looks the symbol up by this
// mangled signature, so a release that changes it must not get offsets
static_assert(std::is_same<decltype(&bssl::ssl_log_secret), bool (*)(const SSL *, const char *, bssl::Span<const uint8_t>)>::value, "ssl_log_secret signature changed");
static_assert(std::is_trivially_copyable<bssl::Span<const uint8_t>>::value && (sizeof(bssl::Span<const uint8_t>) == 2 * sizeof(void *)), "Span is no longer passed in two registers");

template <typename T, typename = void>
struct has_version : std::false_type {
};

template <typename T>
struct has_version<T, std::void_t<decltype(&T::version)>> : std::true_type {
};

// a template, so the offsetof of the branch not taken is never instantiated
template <typename SSL_T, typename S3_T>
constexpr unsigned long version_offset()
{
	if constexpr (has_version<SSL_T>::value)
	{
		return offsetof(SSL_T, version);
	}
	else
	{
		return offsetof(S3_T, version);
	}
}

extern "C" const unsigned long decerter_offset_version = version_offset<ssl_st, bssl::SSL3_STATE>();
extern "C" const unsigned long decerter_offset_version_in_s3 = has_version<ssl_st>::value ? 0 : 1;
extern "C" const unsigned long decerter_offset_s3 = offsetof(ssl_st, s3);
extern "C" const unsigned long decerter_offset_client_random = offsetof(bssl::SSL3_STATE, client_random);
