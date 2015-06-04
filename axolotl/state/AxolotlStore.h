#ifndef AXOLOTLSTORE_H
#define AXOLOTLSTORE_H

/**
 * @file AxolotlStore.h
 * @brief Combined Interface for a Axolotl storage implementation
 * @ingroup Axolotl++
 * @{
 */

#include "IdentityKeyStore.h"
#include "PreKeyStore.h"
#include "SessionStore.h"
#include "SignedPreKeyStore.h"

namespace axolotl {
class AxolotlStore : public IdentityKeyStore, public PreKeyStore, public SessionStore, public SignedPreKeyStore
{
};
} // namespace
/**
 * @}
 */

#endif // AXOLOTLSTORE_H
