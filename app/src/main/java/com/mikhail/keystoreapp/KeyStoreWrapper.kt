package com.mikhail.keystoreapp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


class KeyStoreWrapper {

    private val keyStore: KeyStore = createAndroidKeyStore()

    fun createAndroidKeyStore(): KeyStore {
        // creates KeyStore instance with given type by traversing the list of registered security Providers, starting with the most preferred one
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore
    }

    fun containsKey(keyAlias: String) = keyStore.containsAlias(keyAlias)

    fun getAndroidKeyStoreSymmetricKey(alias: String): SecretKey? =
        keyStore.getKey(alias, null) as SecretKey?

    fun removeAndroidKeyStoreKey(alias: String) = keyStore.deleteEntry(alias)

    fun generateAndroidKeyStoreSymmetricKey(keyAlias: String): SecretKey {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build()
        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

}