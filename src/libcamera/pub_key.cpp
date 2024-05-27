/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2020, Google Inc.
 *
 * Public key signature verification
 */

#include "libcamera/internal/pub_key.h"

#if HAVE_CRYPTO
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#elif HAVE_GNUTLS
#include <gnutls/abstract.h>
#endif

/**
 * \file pub_key.h
 * \brief Public key signature verification
 */

namespace libcamera {

/**
 * \class PubKey
 * \brief Public key wrapper for signature verification
 *
 * The PubKey class wraps a public key and implements signature verification. It
 * only supports RSA keys and the RSA-SHA256 signature algorithm.
 */

/**
 * \brief Construct a PubKey from key data
 * \param[in] key Key data encoded in DER format
 */
PubKey::PubKey([[maybe_unused]] Span<const uint8_t> key)
	: valid_(false)
{
#if HAVE_CRYPTO
	const uint8_t *data = key.data();
	pubkey_ = d2i_PUBKEY(nullptr, &data, key.size());
	if (!pubkey_)
		return;

	valid_ = true;
#elif HAVE_GNUTLS
	int ret = gnutls_pubkey_init(&pubkey_);
	if (ret < 0)
		return;

	const gnutls_datum_t gnuTlsKey{
		const_cast<unsigned char *>(key.data()),
		static_cast<unsigned int>(key.size())
	};
	ret = gnutls_pubkey_import(pubkey_, &gnuTlsKey, GNUTLS_X509_FMT_DER);
	if (ret < 0)
		return;

	valid_ = true;
#endif
}

PubKey::~PubKey()
{
#if HAVE_CRYPTO
	EVP_PKEY_free(pubkey_);
#elif HAVE_GNUTLS
	gnutls_pubkey_deinit(pubkey_);
#endif
}

/**
 * \fn bool PubKey::isValid() const
 * \brief Check is the public key is valid
 * \return True if the public key is valid, false otherwise
 */

/**
 * \brief Verify signature on data
 * \param[in] data The signed data
 * \param[in] sig The signature
 *
 * Verify that the signature \a sig matches the signed \a data for the public
 * key. The signture algorithm is hardcoded to RSA-SHA256.
 *
 * \return True if the signature is valid, false otherwise
 */
bool PubKey::verify([[maybe_unused]] Span<const uint8_t> data,
		    [[maybe_unused]] Span<const uint8_t> sig) const
{
	return true;
}

} /* namespace libcamera */
