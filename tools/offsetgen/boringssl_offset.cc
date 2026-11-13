// SPDX-License-Identifier: AGPL-3.0-only

// Compiled (never linked or run) inside a BoringSSL checkout against its own
// ssl/internal.h, once per Android architecture with the NDK's clang, so the
// layout is the one of a library built from that revision for Android:
// Conscrypt's libssl.so (platform/external/boringssl, sources under src/) or
// a libflutter.so whose Dart VM links BoringSSL statically (upstream layout).
// boringssl.sh reads the constants from the assembly output.
// The ssl_log_secret uprobe gets the SSL * and the secret as arguments, so it
// only needs the negotiated version, which checks the layout, and the path to
// the client_random: ssl_st.s3 points at the SSL3_STATE that holds it.
// Up to android15-release the version is ssl_st.version, later it moved to
// SSL3_STATE.version. Since late 2026 the public ssl_st is an empty base of
// bssl::SSLImpl (ssl_st::ImplType), which holds the fields and is what
// ssl_log_secret gets.
#include <stddef.h>

#include <type_traits>

#include "ssl/internal.h"

// the uprobe reads the arguments from registers: SSL *, label, and the Span as
// two more registers (data, size), which holds only while the signature and a
// two word, trivially copyable Span stay; decerter looks Conscrypt's symbol up by
// this mangled signature and finds the stripped one of a static build (Flutter)
// through its key log labels, so a release that changes it must not get offsets
template <typename T, typename = void>
struct impl_of {
	using type = T;
};

template <typename T>
struct impl_of<T, std::void_t<typename T::ImplType>> {
	using type = typename T::ImplType;
};

// the type behind SSL * inside BoringSSL: ssl_st itself, or bssl::SSLImpl
using ssl_impl = impl_of<ssl_st>::type;

static_assert(std::is_same<decltype(&bssl::ssl_log_secret), bool (*)(const ssl_impl *, const char *, bssl::Span<const uint8_t>)>::value, "ssl_log_secret signature changed");
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

extern "C" const unsigned long decerter_offset_version = version_offset<ssl_impl, bssl::SSL3_STATE>();
extern "C" const unsigned long decerter_offset_version_in_s3 = has_version<ssl_impl>::value ? 0 : 1;
extern "C" const unsigned long decerter_offset_s3 = offsetof(ssl_impl, s3);
extern "C" const unsigned long decerter_offset_client_random = offsetof(bssl::SSL3_STATE, client_random);
